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
  }

  stages {
    stage('Checkout') {
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
        sh '''
          set -eu
          if [ -n "${GIT_PREVIOUS_SUCCESSFUL_COMMIT:-}" ]; then
            python3 scripts/classify_changes.py --base "$GIT_PREVIOUS_SUCCESSFUL_COMMIT" \
              --json-out artifacts/changed-paths.json --env-out artifacts/changed-paths.env
          else
            python3 scripts/classify_changes.py --full \
              --json-out artifacts/changed-paths.json --env-out artifacts/changed-paths.env
          fi
        '''
        script {
          readFile('artifacts/changed-paths.env').split('\n').each { line ->
            if (line) {
              def fields = line.split('=', 2)
              switch (fields[0]) {
                case 'CHANGED_SERVICES':
                  env.CHANGED_SERVICES = fields[1]
                  break
                case 'SHOULD_RUN_PLATFORM_SYNC':
                  env.SHOULD_RUN_PLATFORM_SYNC = fields[1]
                  break
                case 'SHOULD_RUN_ATHEROS_SEARCH':
                  env.SHOULD_RUN_ATHEROS_SEARCH = fields[1]
                  break
                case 'SHOULD_RUN_SCHEMA_MIGRATOR':
                  env.SHOULD_RUN_SCHEMA_MIGRATOR = fields[1]
                  break
                case 'SHOULD_RUN_OCTOPUS':
                  env.SHOULD_RUN_OCTOPUS = fields[1]
                  break
                case 'SHOULD_RUN_SENSOR':
                  env.SHOULD_RUN_SENSOR = fields[1]
                  break
                case 'SHOULD_PUBLISH_REDPANDA_MAINT':
                  env.SHOULD_PUBLISH_REDPANDA_MAINT = fields[1]
                  break
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
        sh '''
          set -eu
          if docker context inspect "$DOCKER_CONTEXT_NAME" >/dev/null 2>&1; then
            docker context rm --force "$DOCKER_CONTEXT_NAME" >/dev/null
          fi
          docker context create "$DOCKER_CONTEXT_NAME" \
            --docker "host=$DOCKER_HOST,ca=$DOCKER_CERT_PATH/ca.pem,cert=$DOCKER_CERT_PATH/cert.pem,key=$DOCKER_CERT_PATH/key.pem" >/dev/null
           env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
             DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker version
           if [ "$SUBMODULE_CI_READY" != true ] && {
             [ "$SHOULD_RUN_OCTOPUS" = true ] || [ "$SHOULD_RUN_SCHEMA_MIGRATOR" = true ];
           }; then
             env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
               DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker pull pgvector/pgvector:pg16
           fi
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
            sh '''
              set -eu
              python3 -c "import json, glob; [json.load(open(f)) for f in glob.glob('cyber-stack/base/telemetry/config/grafana/dashboards/*.json')]"
              bash -n cyber-stack/base/redpanda-maintenance/redpanda-daily-clean.sh
              python3 scripts/check_redpanda_maintenance.py
              tar -cf - cyber-stack/base/redpanda-maintenance/redpanda-daily-clean.sh | docker run --rm -i koalaman/shellcheck-alpine:v0.10.0 \
                sh -c 'tar --no-same-owner -xf - && shellcheck /cyber-stack/base/redpanda-maintenance/redpanda-daily-clean.sh'
              awk -F'|' '
                /^[[:space:]]+[[:alnum:]._-]+\\|/ && (NF != 5 || $5 == "") {
                  print "topic manifest row is missing retention.bytes: " $0 > "/dev/stderr"
                  invalid = 1
                }
                END { exit invalid }
              ' cyber-stack/base/platform-config/configmap.yaml
              tar -cf - cyber-stack/base/telemetry/config/prometheus/rules | docker run --rm -i \
                --entrypoint sh \
                prom/prometheus:v3.2.1@sha256:508729e0e2d18e11fd742a5a5ca70e557b940a93948c3c95fd0123a6fd538b69 \
                -c 'tar --no-same-owner -xf - && promtool check rules cyber-stack/base/telemetry/config/prometheus/rules/*.yml'
            '''
            sh 'make jenkins-plugin-audit'
            sh "python3 -m unittest discover -s scripts/tests -p 'test_*.py' -v"
          }
        }
        stage('Platform sync') {
          options { timeout(time: 30, unit: 'MINUTES') }
          steps {
            sh '''
              set -eu
              if [ "$SHOULD_RUN_PLATFORM_SYNC" != true ]; then echo 'skipped: no platform-sync changes'; exit 0; fi
              docker_cmd() {
                env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
                  DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker "$@"
              }
              tar -cf - . | docker_cmd run --rm -i -w /workspace \
                golang:1.26-bookworm \
                sh -c 'tar --no-same-owner -xf - && make platform-sync-lint'
            '''
          }
        }
        stage('Atheros search') {
          options { timeout(time: 30, unit: 'MINUTES') }
          steps {
            sh '''
              set -eu
              if [ "$SUBMODULE_CI_READY" = true ] || [ "$SHOULD_RUN_ATHEROS_SEARCH" != true ]; then echo 'skipped: delegated or no integration-console bump'; exit 0; fi
              docker_cmd() {
                env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
                  DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker "$@"
              }
              tar -cf - . | docker_cmd run --rm -i -w /workspace \
                golang:1.26-bookworm \
                sh -c 'tar --no-same-owner -xf - && make atheros-search-test'
            '''
          }
        }
        stage('Schema migrator') {
          options { timeout(time: 60, unit: 'MINUTES') }
          steps {
            sh '''
              set -eu
              if [ "$SUBMODULE_CI_READY" = true ] || [ "$SHOULD_RUN_SCHEMA_MIGRATOR" != true ]; then echo 'skipped: delegated or no schema-migrator bump'; exit 0; fi
              docker_cmd() {
                env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
                  DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker "$@"
              }
              tar -cf - . | docker_cmd run --rm -i -w /workspace \
                -v /var/run/docker.sock:/var/run/docker.sock \
                azul/zulu-openjdk:21 \
                sh -c 'tar --no-same-owner -xf - && cd apps/schema-migrator && apt-get -o Dir::Etc::sourceparts="-" update && apt-get install -y --no-install-recommends curl bash && curl -fsSL https://github.com/sbt/sbt/releases/download/v1.12.14/sbt-1.12.14.tgz | tar xz -C /opt && ln -s /opt/sbt/bin/sbt /usr/local/bin/sbt && sbt -Dsbt.supershell=false "Test / testFull"'
            '''
          }
        }
        stage('Octopus') {
          options { timeout(time: 60, unit: 'MINUTES') }
          steps {
            sh '''
              set -eu
              if [ "$SUBMODULE_CI_READY" = true ] || [ "$SHOULD_RUN_OCTOPUS" != true ]; then echo 'skipped: delegated or no Octopus bump'; exit 0; fi
              docker_cmd() {
                env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
                  DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker "$@"
              }
              coverage_container="octopus-coverage-${BUILD_NUMBER}"
              cleanup_coverage_container() {
                docker_cmd rm --force "$coverage_container" >/dev/null 2>&1 || true
              }
              trap cleanup_coverage_container EXIT
              tar -cf - . | docker_cmd run --name "$coverage_container" -i -w /workspace \
                -v /var/run/docker.sock:/var/run/docker.sock \
                azul/zulu-openjdk:21 \
                sh -c 'tar --no-same-owner -xf - && cd services/octopus && apt-get -o Dir::Etc::sourceparts="-" update && apt-get install -y --no-install-recommends curl bash python3 && curl -fsSL https://github.com/sbt/sbt/releases/download/v1.12.14/sbt-1.12.14.tgz | tar xz -C /opt && ln -s /opt/sbt/bin/sbt /usr/local/bin/sbt && OCTOPUS_REQUIRE_DOCKER=true sbt -Dsbt.supershell=false jacoco && python3 scripts/check_coverage.py target/scala-3.3.8/jacoco/report/jacoco.xml'
              mkdir -p artifacts/octopus-coverage
              docker_cmd cp "$coverage_container:/workspace/services/octopus/target/scala-3.3.8/jacoco/report" artifacts/octopus-coverage/jacoco
              docker_cmd cp "$coverage_container:/workspace/services/octopus/target/cucumber" artifacts/octopus-coverage/cucumber
              cleanup_coverage_container
              trap - EXIT
            '''
            archiveArtifacts artifacts: 'artifacts/octopus-coverage/**', allowEmptyArchive: true, fingerprint: true
          }
        }
        stage('Sensor') {
          options { timeout(time: 30, unit: 'MINUTES') }
          steps {
            sh '''
              set -eu
              if [ "$SHOULD_RUN_SENSOR" != true ]; then echo 'skipped: no sensor changes'; exit 0; fi
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
      when {
        expression { env.CHANGED_SERVICES || env.SHOULD_PUBLISH_REDPANDA_MAINT == 'true' }
      }
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
            --environment prod --only "$CHANGED_SERVICES" --reuse-submodules "$SUBMODULE_CI_READY" \
            --tag "$build_tag" --build-date "$build_date" \
            --source-revision "$source_revision" --builder "$BUILDER" \
            --platform linux/amd64 --registry-plain-http "$REGISTRY_PLAIN_HTTP" \
            --max-workers 3 --manifest-out "$RELEASE_MANIFEST" \
            --commands-out "$BUMP_COMMANDS_REPORT" --make-command make
          echo
          echo '=== Manual production digest update report ==='
          cat "$BUMP_COMMANDS_REPORT"
          if [ "$SHOULD_PUBLISH_REDPANDA_MAINT" = true ]; then
            env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
              DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" make --no-print-directory publish-redpanda-maint \
            TAG="$build_tag" BUILD_DATE="$build_date" BUILDER="$BUILDER" PLATFORM=linux/amd64 \
            REGISTRY="$REGISTRY" REGISTRY_PLAIN_HTTP="$REGISTRY_PLAIN_HTTP" \
            PUBLISH_REPOSITORY="$REGISTRY/redpanda-maint" \
            PUBLISH_METADATA_FILE=artifacts/redpanda-maint-buildx.json
          redpanda_maint_digest="$(python3 scripts/image_contract.py buildx-digest artifacts/redpanda-maint-buildx.json)"
          echo "redpanda-maint pushed digest: $redpanda_maint_digest"
          echo 'Pin that digest and add ../../../base/redpanda-maintenance to the reviewed prod data-plane slice only after the platform Secret exists.'
          else
            echo 'skipped: no redpanda-maintenance changes'
          fi
        '''
        archiveArtifacts artifacts: 'artifacts/release-manifest.json,artifacts/bump-digest-commands.txt,artifacts/redpanda-maint-buildx.json', fingerprint: true
      }
    }
  }
}
