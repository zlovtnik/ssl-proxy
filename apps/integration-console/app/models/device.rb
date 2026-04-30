class Device < ApplicationRecord
  self.primary_key = "mac_id"

  normalizes :wg_pubkey, :claim_token_hash, :display_name, :username, :hostname, :os_hint, :notes,
    with: ->(value) { value.to_s.strip.presence }
  normalizes :mac_hint, with: ->(value) { normalize_mac(value) || value.to_s.strip.downcase.presence }

  before_validation :assign_mac_id

  validates :mac_id, presence: true,
    format: { with: /\A[0-9a-f]{2}(?::[0-9a-f]{2}){5}\z/ }
  validates :mac_hint,
    presence: true,
    format: { with: /\A[0-9a-f]{2}(?::[0-9a-f]{2}){5}\z/, allow_blank: true },
    uniqueness: { case_sensitive: false }

  scope :ordered, -> { order(Arel.sql("lower(COALESCE(display_name, username, hostname, mac_hint, mac_id)) ASC")) }
  scope :search, ->(query) {
    sanitized = query.to_s.strip.downcase
    if sanitized.blank?
      all
    else
      normalized = normalize_mac(sanitized) if sanitized.match?(/\A[0-9a-f:.-]+\z/i)
      mac_pattern = "%#{sanitize_sql_like(normalized || sanitized)}%"
      pattern = "%#{sanitize_sql_like(sanitized)}%"
      where(
        "lower(mac_id) LIKE :mac_q OR lower(COALESCE(display_name, '')) LIKE :q OR lower(COALESCE(username, '')) LIKE :q OR lower(COALESCE(hostname, '')) LIKE :q OR lower(COALESCE(os_hint, '')) LIKE :q OR lower(COALESCE(mac_hint, '')) LIKE :mac_q",
        q: pattern,
        mac_q: mac_pattern
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
    display_name.presence || username.presence || hostname.presence || mac_hint.presence || mac_id
  end

  def device_id
    mac_id
  end

  private

  def assign_mac_id
    normalized = self.class.normalize_mac(mac_hint.presence || mac_id)
    self.mac_hint = normalized if normalized.present?
    self.mac_id = normalized if normalized.present?
  end
end
