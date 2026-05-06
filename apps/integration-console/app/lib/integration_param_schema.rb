module IntegrationParamSchema
  SCHEMAS = {
    "nats" => {
      "url" => { "type" => "string", "label" => "NATS URL", "placeholder" => "nats://127.0.0.1:4222" },
      "subject" => { "type" => "string", "label" => "Subject", "placeholder" => "wireless.audit" },
      "consumer_name" => { "type" => "string", "label" => "Consumer" }
    },
    "postgres" => {
      "url" => { "type" => "password", "label" => "Connection URL" },
      "table" => { "type" => "string", "label" => "Table" },
      "batch_size" => { "type" => "integer", "label" => "Batch size", "default" => 1000 }
    },
    "s3" => {
      "bucket" => { "type" => "string", "label" => "Bucket" },
      "prefix" => { "type" => "string", "label" => "Key prefix" },
      "access_key_id" => { "type" => "string", "label" => "Access Key ID" },
      "secret_access_key" => { "type" => "password", "label" => "Secret Access Key" },
      "region" => { "type" => "string", "label" => "Region", "default" => "us-east-1" }
    },
    "http" => {
      "url" => { "type" => "string", "label" => "Endpoint URL" },
      "method" => { "type" => "select", "label" => "Method", "options" => %w[GET POST PUT], "default" => "POST" },
      "auth_header" => { "type" => "password", "label" => "Authorization header" },
      "batch_size" => { "type" => "integer", "label" => "Records per request", "default" => 500 }
    }
  }.freeze

  module_function

  def types
    SCHEMAS.keys
  end

  def schema_for(type)
    SCHEMAS[type.to_s] || {}
  end

  def sensitive_key?(type, key)
    schema_for(type).dig(key.to_s, "type") == "password"
  end

  def masked_params(type, params)
    params.to_h.each_with_object({}) do |(key, value), memo|
      memo[key.to_s] = sensitive_key?(type, key) && value.present? ? "********" : value
    end
  end

  def safe_overrides(type, params)
    params.to_h.each_with_object({}) do |(key, value), memo|
      memo[key.to_s] = value unless sensitive_key?(type, key)
    end
  end
end
