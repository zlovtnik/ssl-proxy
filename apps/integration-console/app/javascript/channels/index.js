import consumer from "channels/consumer"

consumer.subscriptions.create("LiveAuditChannel", {
  received(data) {
    window.dispatchEvent(new CustomEvent("live-audit", { detail: data }))
  }
})

consumer.subscriptions.create("SensorHealthChannel", {
  received(data) {
    window.dispatchEvent(new CustomEvent("sensor-health", { detail: data }))
  }
})

consumer.subscriptions.create("AlertChannel", {
  received(data) {
    window.dispatchEvent(new CustomEvent("sensor-alert", { detail: data }))
  }
})
