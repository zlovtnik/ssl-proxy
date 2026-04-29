require "test_helper"
require "axe-capybara"
require "axe/matchers/be_axe_clean"

class ApplicationSystemTestCase < ActionDispatch::SystemTestCase
  driven_by :selenium, using: :headless_chrome, screen_size: [1400, 1000]

  def assert_axe_clean
    matcher = Axe::Matchers.be_axe_clean
    assert matcher.matches?(page), matcher.failure_message
  end
end
