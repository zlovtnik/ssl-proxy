require "test_helper"

class WirelessAuditIdentityTest < ActiveSupport::TestCase
  test "blank search returns none" do
    assert WirelessAuditIdentity.search("").where_clause.contradiction?
  end
end
