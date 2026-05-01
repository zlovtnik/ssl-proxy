import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static values = {
    recentUrl: String
  }

  connect() {
    this.rows = []
    this.seen = new Set()
    this.lastObservedAt = null
    this.list = this.element.querySelector("[data-live-feed-target='list']")
    this.handleAudit = (event) => this.prepend(event.detail)
    this.pollTimer = window.setInterval(() => this.fetchRecent(), 10000)

    window.addEventListener("live-audit", this.handleAudit)
    this.fetchRecent()
  }

  disconnect() {
    window.removeEventListener("live-audit", this.handleAudit)
    window.clearInterval(this.pollTimer)
  }

  async fetchRecent() {
    if (!this.hasRecentUrlValue) return

    const url = new URL(this.recentUrlValue, window.location.origin)
    if (this.lastObservedAt) url.searchParams.set("after", this.lastObservedAt)
    url.searchParams.set("limit", "25")

    const response = await fetch(url, { headers: { accept: "application/json" } }).catch(() => null)
    if (!response?.ok) return

    let recentRows
    try {
      recentRows = await response.json()
    } catch (error) {
      console.warn("Unable to parse recent audit rows.", error)
      return
    }

    if (!Array.isArray(recentRows)) return
    recentRows.reverse().forEach((row) => this.prepend(row))
  }

  prepend(data) {
    if (!data || !this.list) return

    const key = this.rowKey(data)
    if (key && this.seen.has(key)) return

    const row = {
      key,
      text: [data.observed_at || "", data.sensor_id || "unknown", data.frame_subtype || data.event_type || "event", data.ssid || ""].join(" ").trim()
    }

    this.replaceRows([row, ...this.rows].slice(0, 25))

    if (data.observed_at && (!this.lastObservedAt || data.observed_at > this.lastObservedAt)) {
      this.lastObservedAt = data.observed_at
    }
  }

  replaceRows(nextRows) {
    this.rows = nextRows
    this.seen = new Set(this.rows.map((row) => row.key).filter(Boolean))
    this.render()
  }

  render() {
    this.list.replaceChildren()

    if (this.rows.length === 0) {
      this.list.appendChild(this.rowElement("Waiting for audit events.", "live-row live-row-empty"))
      return
    }

    this.rows.forEach((row) => {
      this.list.appendChild(this.rowElement(row.text, "live-row"))
    })
  }

  rowElement(text, className) {
    const item = document.createElement("li")
    item.className = className
    item.textContent = text
    return item
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
