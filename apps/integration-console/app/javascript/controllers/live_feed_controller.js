import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  static targets = ["list"]

  connect() {
    this.handleAudit = (event) => this.prepend(event.detail)
    window.addEventListener("live-audit", this.handleAudit)
  }

  disconnect() {
    window.removeEventListener("live-audit", this.handleAudit)
  }

  prepend(data) {
    if (!this.hasListTarget) return

    const row = document.createElement("li")
    row.className = "live-row"
    row.textContent = `${data.observed_at || ""} ${data.sensor_id || "unknown"} ${data.frame_subtype || data.event_type || "event"} ${data.ssid || ""}`
    this.listTarget.prepend(row)

    while (this.listTarget.children.length > 25) {
      this.listTarget.lastElementChild.remove()
    }
  }
}
