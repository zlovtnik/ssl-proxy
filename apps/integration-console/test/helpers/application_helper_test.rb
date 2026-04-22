require "test_helper"

class ApplicationHelperTest < ActionView::TestCase
  test "display mac masks by default" do
    assert_equal "XX:XX:XX:XX:44:55", display_mac("00:11:22:33:44:55")
  end

  test "display mac can show full value when explicitly enabled" do
    previous = ENV["INTEGRATION_CONSOLE_FULL_MACS"]
    ENV["INTEGRATION_CONSOLE_FULL_MACS"] = "true"

    assert_equal "00:11:22:33:44:55", display_mac("00:11:22:33:44:55")
  ensure
    ENV["INTEGRATION_CONSOLE_FULL_MACS"] = previous
  end

  test "sort link toggles direction and clears page" do
    @request.query_parameters.merge!("sort" => "created_at", "direction" => "asc", "page" => "3")

    html = sort_link_to("Created", :created_at)

    assert_includes html, "direction=desc"
    assert_no_match(/page=3/, html)
    assert_includes html, "sort-link active"
  end
end
