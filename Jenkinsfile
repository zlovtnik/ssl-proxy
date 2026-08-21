pipeline {
  agent any

  options {
    buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '5'))
    disableConcurrentBuilds(abortPrevious: true)
    skipDefaultCheckout(true)
    timestamps()
  }

  environment {
    BUILDER = 'ssl-proxy-jenkins-http-host'
    BUILDER_NETWORK = 'host'
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
        sh 'make octopus-source-integrity'
      }
    }

    stage('Registry and Buildx preflight') {
      options {
        timeout(time: 10, unit: 'MINUTES')
      }
      steps {
        sh '''
          set -eu
          inotify_instances_path=/proc/sys/fs/inotify/max_user_instances
          required_inotify_instances=1024
          inotify_recovery_command='docker compose -f docker-compose.ci.yaml up -d --no-deps --force-recreate jenkins-docker'
          current_inotify_instances="$(cat "$inotify_instances_path")"
          case "$current_inotify_instances" in
            ''|*[!0-9]*)
              echo "CI host $inotify_instances_path contains an invalid value: $current_inotify_instances" >&2
              echo "From the CI deployment checkout, run: $inotify_recovery_command" >&2
              exit 1
              ;;
          esac
          if [ "$current_inotify_instances" -lt "$required_inotify_instances" ]; then
            echo "CI host $inotify_instances_path is $current_inotify_instances; at least $required_inotify_instances is required." >&2
            echo "From the CI deployment checkout, run: $inotify_recovery_command" >&2
            exit 1
          fi
          if docker context inspect "$DOCKER_CONTEXT_NAME" >/dev/null 2>&1; then
            docker context rm --force "$DOCKER_CONTEXT_NAME" >/dev/null
          fi
          docker context create "$DOCKER_CONTEXT_NAME" \
            --docker "host=$DOCKER_HOST,ca=$DOCKER_CERT_PATH/ca.pem,cert=$DOCKER_CERT_PATH/cert.pem,key=$DOCKER_CERT_PATH/key.pem" \
            >/dev/null
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
            BUILDER_NETWORK="$BUILDER_NETWORK" \
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

    stage('Production revision gate') {
      when {
        expression { currentBuild.currentResult == 'SUCCESS' }
      }
      options {
        timeout(time: 35, unit: 'MINUTES')
      }
      steps {
        withCredentials([
          file(
            credentialsId: 'ssl-proxy-prod-readonly-kubeconfig',
            variable: 'PROD_KUBECONFIG'
          )
        ]) {
          sh '''
            expected_revision="$(git rev-parse HEAD)"
            KUBECONFIG="$PROD_KUBECONFIG" make production-gate \
              PRODUCTION_GATE_REVISION="$expected_revision"
          '''
        }
      }
    }
  }

}
