import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["list"]
  static values = {
    recentUrl: String
  }

  connect() {
    this.seen = new Set()
    this.lastObservedAt = null
    this.handleAudit = (event) => this.prepend(event.detail)
    window.addEventListener("live-audit", this.handleAudit)
    this.pollTimer = window.setInterval(() => this.fetchRecent(), 10000)
    this.fetchRecent()
  }

  disconnect() {
    window.removeEventListener("live-audit", this.handleAudit)
    if (this.pollTimer) window.clearInterval(this.pollTimer)
  }

  prepend(data) {
    if (!this.hasListTarget) return
    const key = this.rowKey(data)
    if (key && this.seen.has(key)) return
    if (key) this.seen.add(key)

    const row = document.createElement("li")
    row.className = "live-row"
    row.textContent = `${data.observed_at || ""} ${data.sensor_id || "unknown"} ${data.frame_subtype || data.event_type || "event"} ${data.ssid || ""}`
    this.listTarget.prepend(row)
    if (data.observed_at && (!this.lastObservedAt || data.observed_at > this.lastObservedAt)) {
      this.lastObservedAt = data.observed_at
    }

    while (this.listTarget.children.length > 25) {
      this.listTarget.lastElementChild.remove()
    }
  }

  async fetchRecent() {
    if (!this.hasRecentUrlValue) return

    const url = new URL(this.recentUrlValue, window.location.origin)
    if (this.lastObservedAt) url.searchParams.set("after", this.lastObservedAt)
    url.searchParams.set("limit", "25")

    const response = await fetch(url, { headers: { accept: "application/json" } })
    if (!response.ok) return

    const rows = await response.json()
    rows.reverse().forEach((row) => this.prepend(row))
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
}
