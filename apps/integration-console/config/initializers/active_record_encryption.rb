encryption_config = Rails.application.config.active_record.encryption
required_keys = %w[
  ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY
  ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY
  ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT
].freeze

if Rails.env.development? || Rails.env.test?
  local_defaults = {
    "ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY" => "0" * 32,
    "ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY" => "1" * 32,
    "ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT" => "2" * 32
  }

  encryption_config.primary_key = ENV.fetch(
    "ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY",
    local_defaults.fetch("ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY")
  )
  encryption_config.deterministic_key = ENV.fetch(
    "ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY",
    local_defaults.fetch("ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY")
  )
  encryption_config.key_derivation_salt = ENV.fetch(
    "ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT",
    local_defaults.fetch("ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT")
  )
else
  missing_keys = required_keys.select { |key| ENV[key].blank? }
  if missing_keys.any?
    raise "Missing Active Record encryption configuration: #{missing_keys.join(", ")}"
  end

  encryption_config.primary_key = ENV.fetch("ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY")
  encryption_config.deterministic_key = ENV.fetch("ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY")
  encryption_config.key_derivation_salt = ENV.fetch("ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT")
end
