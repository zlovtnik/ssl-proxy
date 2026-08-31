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
    REGISTRY = "${env.CI_REGISTRY ?: 'registry:5000'}"
    REGISTRY_PLAIN_HTTP = '1'
    RELEASE_MANIFEST = 'artifacts/release-manifest.json'
  }

  stages {
    stage('Checkout and classify') {
      options { timeout(time: 10, unit: 'MINUTES') }
      steps {
        checkout scm
        sh 'git submodule sync --recursive'
        sh 'git submodule update --init --recursive'
        sh 'make octopus-source-integrity'
        script {
          env.IS_MAIN = sh(
            script: 'test "$(git rev-parse HEAD)" = "$(git rev-parse refs/remotes/origin/main)" && printf true || printf false',
            returnStdout: true
          ).trim()
          env.IS_PROMOTION_COMMIT = sh(
            script: '''
              set -eu
              case "$(git log -1 --pretty=%B)" in
                *'[digest-promotion]'*) ;;
                *) printf false; exit 0 ;;
              esac
              git rev-parse HEAD^ >/dev/null 2>&1 || {
                echo 'marked digest promotion commit has no parent' >&2
                exit 1
              }
              changed_paths="$(git diff --name-only HEAD^ HEAD)"
              [ -n "$changed_paths" ] || { printf false; exit 0; }
              unexpected_paths="$(printf '%s\n' "$changed_paths" | grep -Ev \
                '^(cyber-stack/matrix/prod/app-stack/kustomization.yaml|cyber-stack/matrix/prod/data-plane/kustomization.yaml)$' || true)"
              [ -z "$unexpected_paths" ] || {
                echo "marked digest promotion changed unexpected paths:" >&2
                printf '%s\n' "$unexpected_paths" >&2
                exit 1
              }
              printf true
            ''',
            returnStdout: true
          ).trim()
          if (env.IS_MAIN != 'true') {
            error('Image publication and production observation are restricted to origin/main')
          }
        }
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
              docker_cmd run --rm \
                -v "$PWD:/workspace" -w /workspace \
                golang:1.25-bookworm \
                make platform-sync-lint
              docker_cmd run --rm \
                -v "$PWD:/workspace" -w /workspace \
                golang:1.25-bookworm \
                make atheros-search-test
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
              docker_cmd run --rm \
                -v "$PWD:/workspace" -w /workspace/apps/schema-migrator \
                sbtscala/scala-sbt:eclipse-temurin-21 \
                sbt 'Test / testFull'
              docker_cmd run --rm \
                -v "$PWD:/workspace" -w /workspace/services/octopus \
                sbtscala/scala-sbt:eclipse-temurin-21 \
                sbt test
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
              docker_cmd run --rm \
                -v "$PWD:/workspace" -w /workspace \
                rust:1-bookworm \
                bash -c "apt-get update && apt-get install -y ripgrep && cargo test -p atheros-sensor"
              docker_cmd run --rm \
                -v "$PWD:/workspace" -w /workspace \
                rust:1-bookworm \
                bash -c "apt-get update && apt-get install -y ripgrep && make dependency-boundaries"
            '''
          }
        }
      }
    }

    stage('Registry and Buildx preflight') {
      when { expression { env.IS_PROMOTION_COMMIT != 'true' } }
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
      when { expression { env.IS_PROMOTION_COMMIT != 'true' } }
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
            --max-workers 3 --manifest-out "$RELEASE_MANIFEST" --make-command make
        '''
        archiveArtifacts artifacts: 'artifacts/release-manifest.json', fingerprint: true
      }
    }

    stage('Open digest promotion PR') {
      when { expression { env.IS_PROMOTION_COMMIT != 'true' } }
      options { timeout(time: 10, unit: 'MINUTES') }
      steps {
        withCredentials([
          string(credentialsId: 'ssl-proxy-github-promotion-token', variable: 'GITHUB_TOKEN')
        ]) {
          sh '''
            set -eu
            manifest_path="$(cd "$(dirname "$RELEASE_MANIFEST")" && pwd)/$(basename "$RELEASE_MANIFEST")"
            promotion_dir="$(mktemp -d "$WORKSPACE/.digest-promotion.XXXXXX")"
            trap 'rm -rf -- "$promotion_dir"' EXIT HUP INT TERM
            origin_url="$(git remote get-url origin)"
            git clone --no-local --branch main --single-branch "$origin_url" "$promotion_dir"
            cd "$promotion_dir"
            python3 scripts/promote_release.py --manifest "$manifest_path"
          '''
        }
      }
    }

    stage('Observe Wiretrap production') {
      when { expression { env.IS_PROMOTION_COMMIT == 'true' } }
      options { timeout(time: 90, unit: 'MINUTES') }
      steps {
        withCredentials([
          file(credentialsId: 'ssl-proxy-prod-readonly-kubeconfig', variable: 'PROD_KUBECONFIG')
        ]) {
          sh '''
            expected_revision="$(git rev-parse HEAD)"
            KUBECONFIG="$PROD_KUBECONFIG" make production-gate \
              PRODUCTION_GATE_REVISION="$expected_revision" \
              PRODUCTION_GATE_TIMEOUT=85m
          '''
        }
      }
    }
  }
}
