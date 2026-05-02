require "test_helper"

class NetworkClientsControllerTest < ActionDispatch::IntegrationTest
  test "should get index" do
    get network_clients_url
    assert_response :success
  end

  test "should get index as json" do
    get network_clients_url(format: :json)
    assert_response :success
    json = JSON.parse(response.body)
    assert json.key?("rows")
    assert json.key?("fetchedAt")
  end
end
