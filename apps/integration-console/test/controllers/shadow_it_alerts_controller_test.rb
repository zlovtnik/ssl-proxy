require "test_helper"

class ShadowItAlertsControllerTest < ActionDispatch::IntegrationTest
  setup do
    clear_sync_tables("shadow_it_alerts")
  end

  test "index renders shadow alerts" do
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO shadow_it_alerts
        (source_mac, first_occurred_at, last_occurred_at, occurrence_count, destination_bssid, ssid, sensor_id, location_id, signal_dbm, reason, evidence, created_at, updated_at)
      VALUES
        ('aa:bb:cc:dd:ee:01', now(), now(), 1, '10:20:30:40:50:60', 'CorpWiFi', 'sensor-1', 'lab', -42, 'strong_wireless_without_proxy_presence', '{}'::jsonb, now(), now())
    SQL

    get shadow_it_alerts_url

    assert_response :success
    assert_includes response.body, "Last Occurred"
    assert_includes response.body, "CorpWiFi"
    assert_includes response.body, "strong_wireless_without_proxy_presence"
  end
end
