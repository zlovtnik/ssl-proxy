require_relative "boot"

require "rails"
require "active_model/railtie"
require "active_job/railtie"
require "active_record/railtie"
require "action_controller/railtie"
require "action_view/railtie"
require "action_cable/engine"
require "sprockets/railtie"
require "rails/test_unit/railtie"
require "importmap-rails"
require "turbo-rails"
require "stimulus-rails"

Bundler.require(*Rails.groups)

module IntegrationConsole
  class Application < Rails::Application
    config.load_defaults 7.2
    config.time_zone = "UTC"
    config.eager_load_paths << Rails.root.join("app/services")
    config.active_job.queue_adapter = :async
    config.generators.system_tests = nil
  end
end
