pipeline {
  agent any

  options {
    buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '5'))
    disableConcurrentBuilds()
    skipDefaultCheckout(true)
    timestamps()
  }

  environment {
    BUILDER = 'ssl-proxy-jenkins'
    DOCKER_CONTEXT_NAME = 'ssl-proxy-ci-docker'
    REGISTRY = "${env.CI_REGISTRY ?: 'registry:5000'}"
    REGISTRY_PLAIN_HTTP = '1'
  }

  stages {
    stage('Checkout') {
      steps {
        checkout scm
        sh 'git submodule sync --recursive'
        sh 'git submodule update --init --recursive'
      }
    }

    stage('Validate delivery configuration') {
      steps {
        sh 'make docs-check'
        sh 'make gitops-check'
      }
    }

    stage('Registry preflight') {
      steps {
        sh '''
          if ! docker context inspect "$DOCKER_CONTEXT_NAME" >/dev/null 2>&1; then
            docker context create "$DOCKER_CONTEXT_NAME" \
              --docker "host=$DOCKER_HOST,ca=$DOCKER_CERT_PATH/ca.pem,cert=$DOCKER_CERT_PATH/cert.pem,key=$DOCKER_CERT_PATH/key.pem" \
              >/dev/null
          fi
          env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
            DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" docker version
          docker buildx version
          curl -fsS "http://${REGISTRY}/v2/" >/dev/null
        '''
      }
    }

    stage('Build all images') {
      steps {
        sh '''
          build_tag="$(git rev-parse --short=12 HEAD)"
          env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
            DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" make build-all \
            BUILDER="$BUILDER" \
            REGISTRY="$REGISTRY" \
            REGISTRY_PLAIN_HTTP="$REGISTRY_PLAIN_HTTP" \
            TAG="$build_tag"
        '''
      }
    }

    stage('Publish all images') {
      steps {
        sh '''
          build_tag="$(git rev-parse --short=12 HEAD)"
          env -u DOCKER_HOST -u DOCKER_TLS_VERIFY -u DOCKER_CERT_PATH \
            DOCKER_CONTEXT="$DOCKER_CONTEXT_NAME" make publish-all \
            BUILDER="$BUILDER" \
            REGISTRY="$REGISTRY" \
            REGISTRY_PLAIN_HTTP="$REGISTRY_PLAIN_HTTP" \
            TAG="$build_tag"
        '''
      }
    }
  }
}
