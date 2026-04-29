require "securerandom"

class Device < ApplicationRecord
  self.primary_key = "device_id"

  normalizes :wg_pubkey, :claim_token_hash, :display_name, :username, :hostname, :os_hint, :notes,
    with: ->(value) { value.to_s.strip.presence }
  normalizes :mac_hint, with: ->(value) { normalize_mac(value) || value.to_s.strip.downcase.presence }

  before_validation :assign_device_id

  validates :device_id, presence: true
  validates :mac_hint,
    format: { with: /\A[0-9a-f]{2}(?::[0-9a-f]{2}){5}\z/, allow_blank: true },
    uniqueness: { case_sensitive: false, allow_blank: true }

  scope :ordered, -> { order(Arel.sql("lower(COALESCE(display_name, username, hostname, mac_hint, device_id)) ASC")) }
  scope :search, ->(query) {
    sanitized = query.to_s.strip.downcase
    if sanitized.blank?
      all
    else
      pattern = "%#{sanitize_sql_like(sanitized)}%"
      where(
        "lower(device_id) LIKE :q OR lower(COALESCE(display_name, '')) LIKE :q OR lower(COALESCE(username, '')) LIKE :q OR lower(COALESCE(hostname, '')) LIKE :q OR lower(COALESCE(os_hint, '')) LIKE :q OR lower(COALESCE(mac_hint, '')) LIKE :q",
        q: pattern
      )
    end
  }

  def self.normalize_mac(value)
    text = value.to_s.strip.downcase
    return if text.blank?

    hex = text.gsub(/[^0-9a-f]/, "")
    return unless hex.length == 12

    hex.scan(/../).join(":")
  end

  def label
    display_name.presence || username.presence || hostname.presence || mac_hint.presence || device_id
  end

  private

  def assign_device_id
    self.device_id = SecureRandom.uuid if device_id.blank?
  end
end
