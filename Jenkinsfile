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
        sh 'docker version'
        sh 'docker buildx version'
        sh 'curl -fsS "http://${REGISTRY}/v2/" >/dev/null'
      }
    }

    stage('Build all images') {
      steps {
        sh '''
          build_tag="$(git rev-parse --short=12 HEAD)"
          make build-all \
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
          make publish-all \
            BUILDER="$BUILDER" \
            REGISTRY="$REGISTRY" \
            REGISTRY_PLAIN_HTTP="$REGISTRY_PLAIN_HTTP" \
            TAG="$build_tag"
        '''
      }
    }
  }
}
