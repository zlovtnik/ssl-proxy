require "test_helper"

class ShadowItAlertsControllerTest < ActionDispatch::IntegrationTest
  setup do
    clear_sync_tables("shadow_it_alerts")
  end

  test "index renders shadow alerts" do
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO shadow_it_alerts
        (dedupe_key, observed_at, source_mac, destination_bssid, ssid, sensor_id, location_id, signal_dbm, reason, evidence, created_at, updated_at)
      VALUES
        ('shadow-controller-1', now(), 'aa:bb:cc:dd:ee:01', '10:20:30:40:50:60', 'CorpWiFi', 'sensor-1', 'lab', -42, 'strong_wireless_without_proxy_presence', '{}'::jsonb, now(), now())
    SQL

    get shadow_it_alerts_url

    assert_response :success
    assert_includes response.body, "CorpWiFi"
    assert_includes response.body, "strong_wireless_without_proxy_presence"
  end
end
