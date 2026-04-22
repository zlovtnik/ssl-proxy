Rails.application.configure do
  config.enable_reloading = false
  config.eager_load = true
  config.consider_all_requests_local = false
  config.public_file_server.enabled = ENV["RAILS_SERVE_STATIC_FILES"].present?
  config.log_tags = [ :request_id ]
  config.log_level = ENV.fetch("RAILS_LOG_LEVEL", "info")
  config.log_formatter = Logger::Formatter.new
  config.active_record.dump_schema_after_migration = false
  config.force_ssl = ENV.fetch("RAILS_FORCE_SSL", "false") == "true"
end
