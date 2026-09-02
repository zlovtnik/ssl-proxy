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
  }

  stages {
    stage('Checkout and classify') {
      options { timeout(time: 10, unit: 'MINUTES') }
      steps {
        deleteDir()
        checkout scm
        sh '''
          set -eu
          recovery_command='docker compose -f docker-compose.ci.yaml up -d --no-deps --force-recreate jenkins'
          expected_registry="$(python3 scripts/image_contract.py registry-authority --environment prod)"
          if [ -z "${CI_REGISTRY:-}" ]; then
            echo "controller environment drift: CI_REGISTRY is not set; production requires $expected_registry" >&2
            echo 'Confirm SERVER_IP in the deployment .env, then recreate the Jenkins controller:' >&2
            echo "$recovery_command" >&2
            exit 1
          fi
          if [ "$CI_REGISTRY" != "$expected_registry" ]; then
            echo "controller environment drift: CI_REGISTRY=$CI_REGISTRY, but production requires $expected_registry" >&2
            echo 'Confirm SERVER_IP in the deployment .env, then recreate the Jenkins controller:' >&2
            echo "$recovery_command" >&2
            exit 1
          fi
        '''
        script {
          env.REGISTRY = env.CI_REGISTRY
        }
        sh 'git submodule sync --recursive'
        sh 'git submodule update --init --recursive'
        sh 'make octopus-source-integrity'
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

    stage('Docker test preflight') {
      options { timeout(time: 5, unit: 'MINUTES') }
      steps {
        sh '''
          set -eu
          if docker context inspect "$DOCKER_CONTEXT_NAME" >/dev/null 2>&1; then
            docker context rm --force "$DOCKER_CONTEXT_NAME" >/dev/null
          fi
          docker context create "$DOCKER_CONTEXT_NAME" \
            --docker "host=$DOCKER_HOST,ca=$DOCKER_CERT_PATH/ca.pem,cert=$DOCKER_CERT_PATH/cert.pem,key=$DOCKER_CERT_PATH/key.pem" >/dev/null
          env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
            DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker version
        '''
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
            sh 'make jenkins-plugin-audit'
            sh "python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v"
          }
        }
        stage('Platform and search') {
          options { timeout(time: 30, unit: 'MINUTES') }
          steps {
            sh '''
              set -eu
              docker_cmd() {
                env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
                  DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker "$@"
              }
              tar -cf - . | docker_cmd run --rm -i -w /workspace \
                golang:1.26-bookworm \
                sh -c 'tar --no-same-owner -xf - && make platform-sync-lint'
              tar -cf - . | docker_cmd run --rm -i -w /workspace \
                golang:1.26-bookworm \
                sh -c 'tar --no-same-owner -xf - && make atheros-search-test'
            '''
          }
        }
        stage('Scala services') {
          options { timeout(time: 60, unit: 'MINUTES') }
          steps {
            sh '''
              set -eu
              docker_cmd() {
                env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
                  DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker "$@"
              }
              tar -cf - . | docker_cmd run --rm -i -w /workspace \
                -v /var/run/docker.sock:/var/run/docker.sock \
                azul/zulu-openjdk:21 \
                sh -c 'tar --no-same-owner -xf - && cd apps/schema-migrator && apt-get update && apt-get install -y --no-install-recommends curl bash && curl -fsSL https://github.com/sbt/sbt/releases/download/v1.12.14/sbt-1.12.14.tgz | tar xz -C /opt && ln -s /opt/sbt/bin/sbt /usr/local/bin/sbt && sbt -Dsbt.supershell=false "Test / testFull"'
              tar -cf - . | docker_cmd run --rm -i -w /workspace \
                -v /var/run/docker.sock:/var/run/docker.sock \
                azul/zulu-openjdk:21 \
                sh -c 'tar --no-same-owner -xf - && cd services/octopus && apt-get update && apt-get install -y --no-install-recommends curl bash && curl -fsSL https://github.com/sbt/sbt/releases/download/v1.12.14/sbt-1.12.14.tgz | tar xz -C /opt && ln -s /opt/sbt/bin/sbt /usr/local/bin/sbt && sbt test'
            '''
          }
        }
        stage('Sensor') {
          options { timeout(time: 30, unit: 'MINUTES') }
          steps {
            sh '''
              set -eu
              docker_cmd() {
                env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
                  DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker "$@"
              }
              tar -cf - . | docker_cmd run --rm -i -w /workspace \
                rust:1.95.0-slim-bookworm \
                sh -c 'tar --no-same-owner -xf - && apt-get update && apt-get install -y --no-install-recommends build-essential cmake libclang-dev pkg-config libssl-dev libcurl4-openssl-dev libsasl2-dev libpcap-dev ripgrep && cargo test -p atheros-sensor'
              tar -cf - . | docker_cmd run --rm -i -w /workspace \
                rust:1.95.0-slim-bookworm \
                sh -c 'tar --no-same-owner -xf - && apt-get update && apt-get install -y --no-install-recommends build-essential cmake libclang-dev pkg-config libssl-dev libcurl4-openssl-dev libsasl2-dev libpcap-dev ripgrep make && make dependency-boundaries'
            '''
          }
        }
      }
    }

    stage('Registry and Buildx preflight') {
      options { timeout(time: 10, unit: 'MINUTES') }
      steps {
        sh '''
          set -eu
          inotify_instances_path=/proc/sys/fs/inotify/max_user_instances
          required_inotify_instances=1024
          recovery_command='docker compose -f docker-compose.ci.yaml up -d --no-deps --force-recreate jenkins-docker'
          current_inotify_instances="$(cat "$inotify_instances_path")"
          case "$current_inotify_instances" in
            ''|*[!0-9]*) echo "invalid inotify capacity: $current_inotify_instances" >&2; echo "$recovery_command" >&2; exit 1 ;;
          esac
          [ "$current_inotify_instances" -ge "$required_inotify_instances" ] || {
            echo "at least $required_inotify_instances inotify instances are required" >&2
            echo "$recovery_command" >&2
            exit 1
          }
          if docker context inspect "$DOCKER_CONTEXT_NAME" >/dev/null 2>&1; then
            docker context rm --force "$DOCKER_CONTEXT_NAME" >/dev/null
          fi
          docker context create "$DOCKER_CONTEXT_NAME" \
            --docker "host=$DOCKER_HOST,ca=$DOCKER_CERT_PATH/ca.pem,cert=$DOCKER_CERT_PATH/cert.pem,key=$DOCKER_CERT_PATH/key.pem" >/dev/null
          env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
            DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker version
          curl --fail --silent --show-error --connect-timeout 5 --max-time 15 \
            --retry 2 --retry-all-errors --retry-delay 2 "http://${REGISTRY}/v2/" >/dev/null
          env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
            DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" make buildx-ready \
            BUILDER="$BUILDER" BUILDER_NETWORK="$BUILDER_NETWORK" \
            REGISTRY="$REGISTRY" REGISTRY_PLAIN_HTTP="$REGISTRY_PLAIN_HTTP"
        '''
      }
    }

    stage('Publish immutable images') {
      options { timeout(time: 75, unit: 'MINUTES') }
      steps {
        sh '''
          set -eu
          mkdir -p artifacts
          source_revision="$(git rev-parse HEAD)"
          build_tag="$(git rev-parse --short=12 HEAD)"
          build_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
          env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
            DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" python3 scripts/publish_images.py \
            --environment prod --tag "$build_tag" --build-date "$build_date" \
            --source-revision "$source_revision" --builder "$BUILDER" \
            --platform linux/amd64 --registry-plain-http "$REGISTRY_PLAIN_HTTP" \
            --max-workers 3 --manifest-out "$RELEASE_MANIFEST" \
            --commands-out "$BUMP_COMMANDS_REPORT" --make-command make
          echo
          echo '=== Manual production digest update report ==='
          cat "$BUMP_COMMANDS_REPORT"
        '''
        archiveArtifacts artifacts: 'artifacts/release-manifest.json,artifacts/bump-digest-commands.txt', fingerprint: true
      }
    }
  }
}
