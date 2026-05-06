encryption_config = Rails.application.config.active_record.encryption

if Rails.env.local? || Rails.env.test?
  encryption_config.primary_key = ENV.fetch("ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY", "0" * 32)
  encryption_config.deterministic_key = ENV.fetch("ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY", "1" * 32)
  encryption_config.key_derivation_salt = ENV.fetch("ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT", "2" * 32)
else
  encryption_config.primary_key = ENV["ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY"] if ENV["ACTIVE_RECORD_ENCRYPTION_PRIMARY_KEY"].present?
  encryption_config.deterministic_key = ENV["ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY"] if ENV["ACTIVE_RECORD_ENCRYPTION_DETERMINISTIC_KEY"].present?
  encryption_config.key_derivation_salt = ENV["ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT"] if ENV["ACTIVE_RECORD_ENCRYPTION_KEY_DERIVATION_SALT"].present?
end
