require "test_helper"

class DashboardControllerTest < ActionDispatch::IntegrationTest
  setup do
    Rails.cache.clear
    Sensor.delete_all
    SensorAlert.delete_all
    NatsTrafficSample.delete_all
    clear_sync_tables("sync_error", "sync_batch", "sync_job", "sync_scan_ingest", "audit_backlog", "shadow_it_alerts")
    sync_connection.execute("DELETE FROM sync_cursor")
    ensure_sync_plane_health_view
  end

  test "index renders async dashboard shell without loading sensor rows" do
    26.times do |index|
      Sensor.create!(
        sensor_id: format("sensor-%02d", index),
        location_id: "lab",
        last_seen_at: index.minutes.ago,
        status: "online"
      )
    end

    get root_url(page: 2)

    assert_response :success
    assert_includes response.body, "dashboard-cards-svelte-root"
    assert_includes response.body, "/health/sensors.json"
    assert_not_includes response.body, "sensor-25"
  end

  test "json cards use conditional response and combined backlog counts" do
    Sensor.create!(sensor_id: "sensor-online", location_id: "lab", last_seen_at: Time.current, status: "online")
    insert_backlog(dedupe_key: "pending-1", status: "pending")
    insert_backlog(dedupe_key: "failed-1", status: "failed")
    insert_backlog(dedupe_key: "sync-failed-1", status: "sync_failed")

    get root_url(format: :json)

    assert_response :success
    payload = JSON.parse(response.body)
    backlog = payload.fetch("counts")
    assert_equal 1, backlog.fetch("pending_backlog")
    assert_equal 2, backlog.fetch("failed_backlog")
    etag = response.headers.fetch("ETag")

    get root_url(format: :json), headers: { "If-None-Match" => etag }

    assert_response :not_modified
    assert_empty response.body
  end

  test "json cards expose derived sync health counts" do
    insert_sync_cursor("wireless.audit")
    insert_sync_ingest(
      dedupe_key: "pending-ingest",
      observed_at: 2.minutes.ago,
      payload: {
        "source_mac" => "00:11:22:33:44:55",
        "bssid" => "aa:bb:cc:dd:ee:ff",
        "ssid" => "lab"
      },
      status: "pending"
    )
    insert_sync_ingest(
      dedupe_key: "failed-global-ingest",
      observed_at: 2.minutes.ago,
      payload: { "source_mac" => "66:77:88:99:aa:bb" },
      stream_name: "sync.scan.request",
      status: "failed"
    )
    insert_backlog(dedupe_key: "pending-backlog", status: "pending")
    insert_shadow_it_alert

    completed_job_id = SecureRandom.uuid
    running_job_id = SecureRandom.uuid
    orphaned_job_id = SecureRandom.uuid
    insert_sync_job(completed_job_id, status: "running", created_at: 10.minutes.ago)
    insert_sync_job(running_job_id, status: "running", created_at: 1.minute.ago)
    insert_sync_job(orphaned_job_id, status: "running", created_at: 10.minutes.ago)
    insert_sync_batch(completed_job_id, status: "completed", dedupe_key: "completed-batch")
    insert_sync_batch(running_job_id, status: "dispatched", dedupe_key: "running-batch")

    get root_url(format: :json)

    assert_response :success
    counts = JSON.parse(response.body).fetch("counts")
    assert_equal 1, counts.fetch("wireless_events_24h")
    assert_equal 1, counts.fetch("pending_ingest")
    assert_equal 1, counts.fetch("open_shadow_it_alerts")
    assert_equal 1, counts.fetch("job_orphans")
    assert_equal 1, counts.fetch("job_effective_running")
    assert_equal 1, counts.fetch("job_effective_completed")

    get root_url

    assert_response :success
    assert_includes response.body, "/health/sync_data.json"
    assert_not_includes response.body, "1 pending, 0 processing, 0 failed"
  end

  test "html dashboard does not block on sync health snapshot" do
    calls = 0
    snapshot = SyncPlaneHealth.from_attributes({})

    SyncPlaneHealth.stub(:snapshot, -> { calls += 1; snapshot }) do
      get root_url
    end

    assert_response :success
    assert_equal 0, calls
  end

  private

  def insert_sync_cursor(stream_name)
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO sync_cursor (stream_name, cursor_value, updated_at)
      VALUES (#{sync_connection.quote(stream_name)}, '0', now())
      ON CONFLICT (stream_name) DO UPDATE
        SET cursor_value = excluded.cursor_value,
            updated_at = excluded.updated_at
    SQL
  end

  def insert_sync_job(job_id, status:, created_at:)
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO sync_job (job_id, stream_name, status, attempt_count, created_at, started_at)
      VALUES (
        #{sync_connection.quote(job_id)}::uuid,
        'wireless.audit',
        #{sync_connection.quote(status)},
        0,
        #{sync_connection.quote(created_at)},
        #{sync_connection.quote(created_at)}
      )
    SQL
  end

  def insert_sync_batch(job_id, status:, dedupe_key:)
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO sync_batch (
        batch_id,
        job_id,
        batch_no,
        payload_ref,
        status,
        row_count,
        attempt_count,
        dedupe_key,
        cursor_start,
        cursor_end
      )
      VALUES (
        #{sync_connection.quote(SecureRandom.uuid)}::uuid,
        #{sync_connection.quote(job_id)}::uuid,
        0,
        #{sync_connection.quote("payload://#{dedupe_key}")},
        #{sync_connection.quote(status)},
        1,
        0,
        #{sync_connection.quote(dedupe_key)},
        '0',
        '1'
      )
    SQL
  end

  def insert_shadow_it_alert
    sync_connection.execute(<<~SQL.squish)
      INSERT INTO shadow_it_alerts (
        source_mac,
        first_occurred_at,
        last_occurred_at,
        occurrence_count,
        destination_bssid,
        ssid,
        reason,
        evidence,
        created_at,
        updated_at
      )
      VALUES (
        '00:11:22:33:44:55',
        now(),
        now(),
        1,
        'aa:bb:cc:dd:ee:ff',
        'lab',
        'strong_wireless_without_proxy_presence',
        '{}'::jsonb,
        now(),
        now()
      )
    SQL
  end
end
