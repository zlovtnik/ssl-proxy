require "aws-sdk-s3"

module IntegrationConsole
  module Minio
    module_function

    def bucket
      ENV.fetch("MINIO_BUCKET", "integration-console-exports")
    end
  end
end

Aws.config.update(
  endpoint: ENV.fetch("MINIO_ENDPOINT", "http://127.0.0.1:9000"),
  access_key_id: ENV["MINIO_ACCESS_KEY_ID"],
  secret_access_key: ENV["MINIO_SECRET_ACCESS_KEY"],
  region: "us-east-1",
  force_path_style: true
)

MINIO_BUCKET = IntegrationConsole::Minio.bucket
