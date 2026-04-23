require "test_helper"

class ShadowItAlertTest < ActiveSupport::TestCase
  setup do
    clear_sync_tables("shadow_it_alerts")
  end

  test "search matches source and bssid fields" do
    insert_shadow_alert(source_mac: "aa:bb:cc:dd:ee:01", destination_bssid: "10:20:30:40:50:60", ssid: "CorpWiFi")

    assert_equal 1, ShadowItAlert.search("10:20").count
    assert_equal 1, ShadowItAlert.search("aa:bb").count
    assert ShadowItAlert.search("").where_clause.contradiction?
  end

  private

  def insert_shadow_alert(source_mac:, destination_bssid:, ssid:)
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO shadow_it_alerts
        (dedupe_key, observed_at, source_mac, destination_bssid, ssid, sensor_id, location_id, signal_dbm, reason, evidence, created_at, updated_at)
      VALUES
        ('shadow-1', now(), #{sync_connection.quote(source_mac)}, #{sync_connection.quote(destination_bssid)}, #{sync_connection.quote(ssid)}, 'sensor-1', 'lab', -42, 'strong_wireless_without_proxy_presence', '{}'::jsonb, now(), now())
    SQL
  end
end
