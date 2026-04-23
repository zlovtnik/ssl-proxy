import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["body", "empty"]
  static values = {
    active: Boolean,
    recentUrl: String
  }

  connect() {
    if (!this.activeValue) return

    this.seen = new Set()
    this.bodyTarget.querySelectorAll("[data-audit-log-id]").forEach((row) => {
      if (row.dataset.auditLogId) this.seen.add(row.dataset.auditLogId)
    })
    this.lastObservedAt = this.latestObservedAt()
    this.handleAudit = (event) => this.prepend(event.detail)
    window.addEventListener("live-audit", this.handleAudit)
    this.pollTimer = window.setInterval(() => this.fetchRecent(), 10000)
    this.fetchRecent()
  }

  disconnect() {
    if (this.handleAudit) window.removeEventListener("live-audit", this.handleAudit)
    if (this.pollTimer) window.clearInterval(this.pollTimer)
  }

  async fetchRecent() {
    if (!this.hasRecentUrlValue) return

    const url = new URL(this.recentUrlValue, window.location.origin)
    if (this.lastObservedAt) url.searchParams.set("after", this.lastObservedAt)
    url.searchParams.set("limit", "25")

    const response = await fetch(url, { headers: { accept: "application/json" } }).catch(() => null)
    if (!response?.ok) return

    const rows = await response.json()
    rows.reverse().forEach((row) => this.prepend(row))
  }

  prepend(data) {
    if (!this.hasBodyTarget || !data) return

    const key = this.rowKey(data)
    if (key && this.seen.has(key)) return
    if (key) this.seen.add(key)

    const row = document.createElement("tr")
    if (data.dedupe_key) row.dataset.auditLogId = data.dedupe_key
    if (data.observed_at) row.dataset.auditLogObservedAt = data.observed_at

    this.appendCell(row, data.observed_at || "", data.show_url)
    this.appendCell(row, data.sensor_id || "")
    this.appendCell(row, data.location_id || "")
    this.appendCell(row, data.frame_subtype || data.event_type || "event")
    this.appendCell(row, data.ssid || "")
    this.appendCell(row, data.source_mac_display || this.maskMac(data.source_mac) || "")
    this.appendCell(row, data.destination_bssid_display || this.maskMac(data.destination_bssid) || "")
    this.appendCell(row, data.signal_dbm ?? "")
    this.appendCell(row, data.raw_len ?? "")
    this.appendCell(row, data.frame_flags_label || "")
    this.appendCell(row, data.security_label || "open/unknown")
    this.appendCell(row, this.shortFingerprint(data.device_fingerprint))
    this.appendCell(row, data.handshake_captured ? "captured" : "")

    if (this.hasEmptyTarget) this.emptyTarget.remove()
    this.bodyTarget.prepend(row)
    this.lastObservedAt = this.latestObservedAt()
    this.trimRows()
  }

  appendCell(row, value, href = null) {
    const cell = document.createElement("td")
    if (href) {
      const link = document.createElement("a")
      link.href = href
      link.textContent = value
      cell.appendChild(link)
    } else {
      cell.textContent = value
    }
    row.appendChild(cell)
  }

  latestObservedAt() {
    const values = Array.from(this.bodyTarget.querySelectorAll("[data-audit-log-observed-at]"))
      .map((row) => row.dataset.auditLogObservedAt)
      .filter(Boolean)
      .sort()
    return values[values.length - 1] || null
  }

  trimRows() {
    while (this.bodyTarget.children.length > 50) {
      this.bodyTarget.lastElementChild.remove()
    }
  }

  rowKey(data) {
    return data.dedupe_key || [
      data.observed_at,
      data.sensor_id,
      data.frame_subtype || data.event_type,
      data.source_mac,
      data.ssid
    ].join("|")
  }

  maskMac(mac) {
    if (!mac) return null
    const parts = String(mac).split(":")
    if (parts.length !== 6) return "masked"
    return `XX:XX:XX:XX:${parts[4]}:${parts[5]}`
  }

  shortFingerprint(value) {
    if (!value) return ""
    return String(value).slice(0, 12)
  }
}
