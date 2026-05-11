class WirelessProbeObservation < ApplicationRecord
  self.table_name = "wireless_probe_observations"

  normalizes :mac_address, :ssid, :bssid, :location_id, :sensor_id,
    with: ->(value) { value.to_s.strip.presence }
  normalizes :mac_address, with: ->(value) { normalize_mac(value) || value.to_s.strip.downcase.presence }

  validates :mac_address, presence: true

  scope :recent, -> { order(last_seen: :desc) }
  scope :by_location, ->(location_id) { where(location_id: location_id) }
  scope :by_sensor, ->(sensor_id) { where(sensor_id: sensor_id) }

  def self.normalize_mac(value)
    text = value.to_s.strip.downcase
    return if text.blank?

    hex = text.gsub(/[^0-9a-f]/, "")
    return unless hex.length == 12

    hex.scan(/../).join(":")
  end

  def self.upsert_observation(attrs)
    mac = normalize_mac(attrs[:mac_address]) || attrs[:mac_address]
    ssid = attrs[:ssid].to_s.strip.presence
    bssid = attrs[:bssid].to_s.strip.downcase.presence

    existing = find_by(mac_address: mac, ssid: ssid, bssid: bssid)

    if existing
      existing.update!(
        rssi: attrs[:rssi],
        frequency: attrs[:frequency],
        last_seen: Time.current,
        observation_count: existing.observation_count + 1,
        location_id: attrs[:location_id].presence || existing.location_id,
        sensor_id: attrs[:sensor_id].presence || existing.sensor_id
      )
    else
      create!(
        mac_address: mac,
        ssid: ssid,
        bssid: bssid,
        rssi: attrs[:rssi],
        frequency: attrs[:frequency],
        location_id: attrs[:location_id],
        sensor_id: attrs[:sensor_id],
        first_seen: Time.current,
        last_seen: Time.current,
        observation_count: 1
      )
    end
  end
end