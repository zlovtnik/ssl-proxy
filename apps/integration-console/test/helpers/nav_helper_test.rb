require "test_helper"

class NavHelperTest < ActionView::TestCase
  tests NavHelper

  test "nav link applies active class for current page" do
    def current_page?(path)
      path == "/alerts"
    end

    html = nav_link_to("Alerts", "/alerts", icon: :alerts)

    assert_includes html, "nav-link active"
  end

  test "nav link omits active class for other pages" do
    def current_page?(_path)
      false
    end

    html = nav_link_to("Alerts", "/alerts", icon: :alerts)

    assert_includes html, "nav-link"
    assert_no_match(/nav-link active/, html)
  end
end
