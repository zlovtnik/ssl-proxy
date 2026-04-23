class AuthorizedWirelessNetwork < ApplicationRecord
  normalizes :ssid, :bssid, :location_id, with: ->(value) { value.to_s.strip.presence }
  normalizes :bssid, with: ->(value) { value.to_s.strip.downcase.presence }

  validates :ssid, presence: true, unless: -> { bssid.present? }
  validates :bssid, presence: true, unless: -> { ssid.present? }

  scope :enabled, -> { where(enabled: true) }
  scope :ordered, -> { order(enabled: :desc, location_id: :asc, ssid: :asc, bssid: :asc) }

  def match_label
    [location_id.presence || "any location", ssid.presence || "any SSID", bssid.presence || "any BSSID"].join(" / ")
  end
end
