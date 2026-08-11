pipeline {
  agent any

  options {
    buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '5'))
    disableConcurrentBuilds()
    skipDefaultCheckout(true)
    timestamps()
  }

  environment {
    BUILDER = 'ssl-proxy-jenkins-http'
    DOCKER_CONTEXT_NAME = 'ssl-proxy-ci-docker'
    REGISTRY = "${env.CI_REGISTRY ?: 'registry:5000'}"
    REGISTRY_PLAIN_HTTP = '1'
  }

  stages {
    stage('Checkout') {
      options {
        timeout(time: 10, unit: 'MINUTES')
      }
      steps {
        checkout scm
        sh 'git submodule sync --recursive'
        sh 'git submodule update --init --recursive'
      }
    }

    stage('Registry and Buildx preflight') {
      options {
        timeout(time: 10, unit: 'MINUTES')
      }
      steps {
        sh '''
          set -eu
          if ! docker context inspect "$DOCKER_CONTEXT_NAME" >/dev/null 2>&1; then
            docker context create "$DOCKER_CONTEXT_NAME" \
              --docker "host=$DOCKER_HOST,ca=$DOCKER_CERT_PATH/ca.pem,cert=$DOCKER_CERT_PATH/cert.pem,key=$DOCKER_CERT_PATH/key.pem" \
              >/dev/null
          fi
          env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
            DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker version
          env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
            DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker buildx version
          curl --fail --silent --show-error \
            --connect-timeout 5 --max-time 15 \
            --retry 2 --retry-all-errors --retry-delay 2 \
            "http://${REGISTRY}/v2/" >/dev/null
          env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
            DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" make buildx-ready \
            BUILDER="$BUILDER" \
            REGISTRY="$REGISTRY" \
            REGISTRY_PLAIN_HTTP="$REGISTRY_PLAIN_HTTP"
        '''
      }
    }

    stage('Validate and publish') {
      failFast false
      parallel {
        stage('Validate delivery configuration') {
          options {
            timeout(time: 15, unit: 'MINUTES')
          }
          steps {
            catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
              sh 'make docs-check'
            }
            catchError(buildResult: 'FAILURE', stageResult: 'FAILURE') {
              sh 'make gitops-check'
            }
          }
        }

        stage('Publish images') {
          steps {
            script {
              def services = sh(
                script: 'make --no-print-directory ci-publish-services',
                returnStdout: true
              ).trim().split('\\n').findAll { it }
              if (services.isEmpty()) {
                error('ci-publish-services returned no image publish targets')
              }

              def publishBranches = [:]
              services.each { service ->
                def serviceName = service
                publishBranches["Publish ${serviceName}"] = {
                  timeout(time: 30, unit: 'MINUTES') {
                    retry(2) {
                      sh """
                        build_tag=\"\$(git rev-parse --short=12 HEAD)\"
                        env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \\
                          DOCKER_CONTEXT=\"$DOCKER_CONTEXT_NAME\" make publish-${serviceName} \\
                          BUILDER=\"$BUILDER\" \\
                          BUILDX_READY=1 \\
                          REGISTRY=\"$REGISTRY\" \\
                          REGISTRY_PLAIN_HTTP=\"$REGISTRY_PLAIN_HTTP\" \\
                          TAG=\"\$build_tag\"
                      """
                    }
                  }
                }
              }
              publishBranches.failFast = false
              parallel publishBranches
            }
          }
        }
      }
    }
  }

  post {
    failure {
      script {
        def failureResult = currentBuild.currentResult ?: 'FAILURE'
        def failureCommit = sh(script: 'git rev-parse HEAD 2>/dev/null || printf unknown', returnStdout: true).trim()
        try {
          withCredentials([string(credentialsId: 'ssl-proxy-ci-failure-webhook', variable: 'FAILURE_WEBHOOK_URL')]) {
            withEnv(["FAILURE_RESULT=${failureResult}", "FAILURE_COMMIT=${failureCommit}"]) {
              sh '''
                payload="$(python3 -c 'import json, os; print(json.dumps({"job": os.environ["JOB_NAME"], "build_url": os.environ["BUILD_URL"], "commit": os.environ["FAILURE_COMMIT"], "result": os.environ["FAILURE_RESULT"]}))')"
                curl --fail --silent --show-error \
                  --connect-timeout 5 --max-time 20 \
                  --retry 2 --retry-all-errors --retry-delay 2 \
                  --request POST --header 'Content-Type: application/json' \
                  --data "$payload" "$FAILURE_WEBHOOK_URL"
              '''
            }
          }
        } catch (notificationError) {
          echo("Failure notification could not be delivered: ${notificationError}")
        }
      }
    }
  }
}
