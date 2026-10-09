pipeline {
  agent any

  options {
    buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '10'))
    disableConcurrentBuilds(abortPrevious: true)
    skipDefaultCheckout(true)
    timestamps()
    timeout(time: 180, unit: 'MINUTES')
  }

  environment {
    BUILDER = 'ssl-proxy-jenkins-http-host'
    BUILDER_NETWORK = 'host'
    DOCKER_CONTEXT_NAME = 'ssl-proxy-ci-docker'
    REGISTRY_PLAIN_HTTP = '1'
    RELEASE_MANIFEST = 'artifacts/release-manifest.json'
    BUMP_COMMANDS_REPORT = 'artifacts/bump-digest-commands.txt'
    SUBMODULE_CI_READY = 'false'
    CI_USE_DOCKER_CONTEXT = 'true'
  }

  stages {
    stage('Checkout') {
      options { timeout(time: 10, unit: 'MINUTES') }
      steps {
        deleteDir()
        checkout scm
        sh 'bash scripts/ci/registry-check.sh'
        script {
          env.REGISTRY = env.CI_REGISTRY
        }
        script {
          env.IS_MAIN = sh(
            script: 'test "$(git rev-parse HEAD)" = "$(git rev-parse refs/remotes/origin/main)" && printf true || printf false',
            returnStdout: true
          ).trim()
          if (env.IS_MAIN != 'true') {
            error('Image publication is restricted to origin/main')
          }
        }
      }
    }

    stage('Classify changes') {
      steps {
        sh 'bash scripts/ci/classify-changes.sh'
        script {
          def allowedKeys = [
            'CHANGED_SERVICES', 'SHOULD_RUN_PLATFORM_SYNC',
            'SHOULD_RUN_STATS_READER', 'SHOULD_RUN_ATHEROS_SEARCH',
            'SHOULD_RUN_ATHEROS_SEARCH_CONTRACTS', 'SHOULD_RUN_SCHEMA_MIGRATOR',
            'SHOULD_RUN_OCTOPUS', 'SHOULD_RUN_SENSOR',
            'SHOULD_PUBLISH_REDPANDA_MAINT', 'SHOULD_PUBLISH_STATS_READER'
          ]
          readFile('artifacts/changed-paths.env').split('\n').each { line ->
            if (line) {
              def fields = line.split('=', 2)
              if (fields.size() == 2 && allowedKeys.contains(fields[0])) {
                env[fields[0]] = fields[1]
              }
            }
          }
        }
        archiveArtifacts artifacts: 'artifacts/changed-paths.json', fingerprint: true
      }
    }

    stage('Prepare pinned submodules') {
      steps {
        // Delivery contracts inspect every pinned submodule's documentation.
        sh 'git submodule sync --recursive'
        sh 'git submodule update --init --recursive'
        sh 'make octopus-source-integrity'
      }
    }

    stage('Docker test preflight') {
      options { timeout(time: 5, unit: 'MINUTES') }
      steps {
        sh 'bash scripts/ci/docker-preflight.sh'
      }
    }

    stage('Validate and test') {
      failFast true
      parallel {
        stage('Delivery contracts') {
          options { timeout(time: 20, unit: 'MINUTES') }
          steps {
            sh 'make docs-check'
            sh 'make gitops-check'
            sh 'bash scripts/ci/delivery.sh'
            sh 'make jenkins-plugin-audit'
            sh "python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v"
          }
        }
        stage('Keycloak login layout') {
          options { timeout(time: 10, unit: 'MINUTES') }
          steps {
            sh 'bash scripts/ci/keycloak-theme.sh'
          }
          post {
            always {
              archiveArtifacts artifacts: 'artifacts/keycloak-theme/**', allowEmptyArchive: true
            }
          }
        }
        stage('Platform sync') {
          options { timeout(time: 30, unit: 'MINUTES') }
          steps {
            sh 'bash scripts/ci/platform-sync.sh'
          }
        }
        stage('Stats reader') {
          options { timeout(time: 30, unit: 'MINUTES') }
          steps {
            sh 'bash scripts/ci/stats-reader.sh'
          }
        }
        stage('Atheros search') {
          options { timeout(time: 30, unit: 'MINUTES') }
          steps {
            sh 'bash scripts/ci/atheros-search.sh'
          }
        }
        stage('Atheros search contracts') {
          options { timeout(time: 30, unit: 'MINUTES') }
          steps {
            sh 'bash scripts/ci/atheros-search-contracts.sh'
          }
        }
        stage('Schema migrator') {
          options { timeout(time: 60, unit: 'MINUTES') }
          steps {
            sh 'bash scripts/ci/schema-migrator.sh'
          }
        }
        stage('Octopus') {
          options { timeout(time: 60, unit: 'MINUTES') }
          steps {
            sh 'bash scripts/ci/octopus.sh'
            archiveArtifacts artifacts: 'artifacts/octopus-coverage/**', allowEmptyArchive: true, fingerprint: true
          }
        }
        stage('Sensor') {
          options { timeout(time: 30, unit: 'MINUTES') }
          steps {
            sh 'bash scripts/ci/sensor.sh'
          }
        }
      }
    }

    stage('Registry and Buildx preflight') {
      when {
        expression { env.CHANGED_SERVICES || env.SHOULD_PUBLISH_REDPANDA_MAINT == 'true' || env.SHOULD_PUBLISH_STATS_READER == 'true' }
      }
      options { timeout(time: 10, unit: 'MINUTES') }
      steps {
        sh 'bash scripts/ci/buildx-preflight.sh'
      }
    }

    stage('Publish immutable images') {
      when {
        expression { env.CHANGED_SERVICES || env.SHOULD_PUBLISH_REDPANDA_MAINT == 'true' || env.SHOULD_PUBLISH_STATS_READER == 'true' }
      }
      options { timeout(time: 75, unit: 'MINUTES') }
      steps {
        sh 'bash scripts/ci/publish.sh'
        archiveArtifacts artifacts: 'artifacts/release-manifest.json,artifacts/bump-digest-commands.txt,artifacts/redpanda-maint-buildx.json,artifacts/stats-reader-buildx.json', fingerprint: true
      }
    }
  }

  post {
    always {
      timeout(time: 5, unit: 'MINUTES') {
        sh label: 'Reclaim CI resources', script: 'if [ -f scripts/ci/cleanup.sh ]; then bash scripts/ci/cleanup.sh; fi'
      }
    }
  }
}
