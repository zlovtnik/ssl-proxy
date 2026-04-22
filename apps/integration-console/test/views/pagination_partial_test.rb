require "test_helper"

class PaginationPartialTest < ActionView::TestCase
  test "renders previous and next links with query params" do
    @current_page = 2
    @total_pages = 3
    request.query_parameters.merge!("q" => "sensor")

    render partial: "shared/pagination"

    assert_includes rendered, "Prev"
    assert_includes rendered, "Next"
    assert_includes rendered, "q=sensor"
    assert_includes rendered, "Page 2 of 3"
  end

  test "disables previous link on first page" do
    @current_page = 1
    @total_pages = 2

    render partial: "shared/pagination"

    assert_includes rendered, "aria-disabled=\"true\""
    assert_includes rendered, "Page 1 of 2"
  end
end
