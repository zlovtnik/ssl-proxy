import { Controller } from "@hotwired/stimulus"

const MAC_RE = /^(?:[0-9a-fA-F]{2}|[xX]{2})(?::(?:[0-9a-fA-F]{2}|[xX]{2})){5}$/

export default class extends Controller {
  static values = {
    inventoryUrl: String,
    recentAuditLogsUrl: String,
    auditLogsUrl: String,
    identitiesUrl: String,
    shadowItUrl: String
  }

  connect() {
    this.card = null
    this.hideTimer = null
    this.showTimer = null
    this.fetchCache = new Map()
    this.enhancedCells = new WeakSet()
    this.enhanceHandler = () => this.enhance()
    this.element.addEventListener("mac-link:enhance", this.enhanceHandler)
    this.enhance()
  }

  disconnect() {
    this.element.removeEventListener("mac-link:enhance", this.enhanceHandler)
    window.clearTimeout(this.hideTimer)
    window.clearTimeout(this.showTimer)
    this.removeCard()
  }

  enhance() {
    this.element.querySelectorAll("td").forEach((cell) => {
      if (this.enhancedCells.has(cell) || cell.querySelector(".mac-chip")) return

      const mac = cell.textContent.trim()
      if (!MAC_RE.test(mac)) return

      this.enhancedCells.add(cell)

      const chip = document.createElement("a")
      chip.className = "mac-chip"
      chip.dataset.mac = mac
      chip.href = this.searchUrl(window.location.pathname, mac)
      chip.setAttribute("aria-label", `Search for MAC ${mac}`)

      const dot = document.createElement("span")
      dot.className = "mac-chip-dot"
      dot.setAttribute("aria-hidden", "true")

      chip.appendChild(dot)
      chip.appendChild(document.createTextNode(mac))

      cell.textContent = ""
      cell.appendChild(chip)

      chip.addEventListener("mouseenter", () => this.show(mac, cell))
      chip.addEventListener("mouseleave", () => this.scheduleHide())
      chip.addEventListener("focus", () => this.show(mac, cell))
      chip.addEventListener("blur", () => this.scheduleHide())
    })
  }

  show(mac, anchor) {
    window.clearTimeout(this.hideTimer)
    window.clearTimeout(this.showTimer)

    this.showTimer = window.setTimeout(() => this._show(mac, anchor), 120)
  }

  async _show(mac, anchor) {
    window.clearTimeout(this.hideTimer)

    if (this.card && this.card.dataset.mac === mac) return

    this.removeCard()

    const card = document.createElement("div")
    card.className = "mac-hover-card"
    card.dataset.mac = mac
    card.innerHTML = this.loadingHTML(mac)

    card.addEventListener("mouseenter", () => window.clearTimeout(this.hideTimer))
    card.addEventListener("mouseleave", () => this.scheduleHide())

    document.body.appendChild(card)
    this.card = card
    this.positionCard(card, anchor)

    try {
      let devices, auditLogs
      if (this.fetchCache.has(mac)) {
        ;({ devices, auditLogs } = this.fetchCache.get(mac))
      } else {
        ;[devices, auditLogs] = await Promise.all([
          this.fetchJson(this.inventoryUrlValue, mac),
          this.fetchJson(this.recentAuditLogsUrlValue, mac)
        ])
        this.fetchCache.set(mac, { devices, auditLogs })
        if (this.fetchCache.size > 50) {
          this.fetchCache.delete(this.fetchCache.keys().next().value)
        }
      }

      const device = this.findDevice(devices, mac)
      const summary = this.auditSummary(auditLogs)

      if (this.card !== card) return
      card.innerHTML = this.filledHTML(mac, device, summary)
      this.bindCardLinks(card, mac)
      this.positionCard(card, anchor)
    } catch {
      if (this.card === card) {
        card.innerHTML = this.errorHTML(mac)
        this.bindCardLinks(card, mac)
        this.positionCard(card, anchor)
      }
    }
  }

  async fetchJson(baseUrl, mac) {
    if (!baseUrl) return []

    const url = new URL(baseUrl, window.location.origin)
    url.searchParams.set("q", this.searchQuery(mac))
    if (!url.searchParams.has("limit")) url.searchParams.set("limit", "100")

    const response = await fetch(url, { headers: { accept: "application/json" } })
    if (!response.ok) throw new Error("MAC lookup failed")

    const data = await response.json()
    return Array.isArray(data) ? data : []
  }

  findDevice(devices, mac) {
    const normalized = mac.toLowerCase()
    return devices.find((device) => device.source_mac?.toLowerCase() === normalized) || devices[0]
  }

  auditSummary(rows) {
    const signals = rows
      .map((row) => Number.parseInt(row.signal_dbm, 10))
      .filter((signal) => Number.isFinite(signal))
    const observedAt = rows.map((row) => row.observed_at).filter(Boolean).sort()
    const firstSeen = observedAt[0]
    const lastSeen = observedAt[observedAt.length - 1]

    if (signals.length === 0) return { count: rows.length, signal: null, firstSeen, lastSeen }

    const min = Math.min(...signals)
    const max = Math.max(...signals)
    const latest = signals[0]
    const signal = min === max ? `${latest} dBm` : `${min} to ${max} dBm`

    return { count: rows.length, signal, firstSeen, lastSeen }
  }

  scheduleHide() {
    window.clearTimeout(this.showTimer)
    this.hideTimer = window.setTimeout(() => this.removeCard(), 200)
  }

  removeCard() {
    if (!this.card) return

    this.card.remove()
    this.card = null
  }

  positionCard(card, anchor) {
    const rect = anchor.getBoundingClientRect()
    const cardWidth = 288
    let left = rect.left + window.scrollX

    if (left + cardWidth > window.innerWidth - 16) {
      left = Math.max(8, window.innerWidth - cardWidth - 16)
    }

    card.style.position = "absolute"
    card.style.zIndex = "9999"
    card.style.top = `${rect.bottom + window.scrollY + 6}px`
    card.style.left = `${left}px`
  }

  loadingHTML(mac) {
    return `
<div class="mhc-header"><span class="mhc-mac">${this.escape(mac)}</span></div>
<div class="mhc-loading">Loading...</div>`
  }

  filledHTML(mac, device, summary) {
    const frames = device?.frame_count ?? summary.count ?? "-"
    const firstSeen = this.formatTime(device?.first_seen || summary.firstSeen)
    const lastSeen = this.formatTime(device?.last_seen || summary.lastSeen)
    const signal = summary.signal || "-"
    const ssid = device?.ssid ? `<span class="mhc-badge">${this.escape(device.ssid)}</span>` : ""
    const services = device?.services ? `<div class="mhc-detail">${this.escape(device.services)}</div>` : ""
    const ips = device?.ip_addresses ? `<div class="mhc-detail">${this.escape(device.ip_addresses)}</div>` : ""

    return `
<div class="mhc-header">
  <span class="mhc-mac">${this.escape(mac)}</span>
  ${ssid}
</div>
<div class="mhc-stats">
  <div class="mhc-stat"><span class="mhc-val">${this.escape(frames)}</span><span class="mhc-lbl">frames</span></div>
  <div class="mhc-stat"><span class="mhc-val">${this.escape(signal)}</span><span class="mhc-lbl">signal</span></div>
  <div class="mhc-stat"><span class="mhc-val">${this.escape(device?.protected_frame_count ?? "-")}</span><span class="mhc-lbl">encrypted</span></div>
</div>
${ips}${services}
<div class="mhc-times">First: ${firstSeen}<br>Last: ${lastSeen}</div>
${this.linksHTML()}`
  }

  errorHTML(mac) {
    return `
<div class="mhc-header"><span class="mhc-mac">${this.escape(mac)}</span></div>
<div class="mhc-loading mhc-error">No MAC summary available.</div>
${this.linksHTML()}`
  }

  linksHTML() {
    return `
<div class="mhc-links">
  <a class="mhc-link" data-action="audit-logs" href="#">Audit logs</a>
  <a class="mhc-link" data-action="identities" href="#">Identities</a>
  <a class="mhc-link" data-action="shadow-it" href="#">Shadow IT</a>
  <a class="mhc-link mhc-copy" data-action="copy" href="#">Copy MAC</a>
</div>`
  }

  bindCardLinks(card, mac) {
    card.querySelectorAll(".mhc-link").forEach((link) => {
      const action = link.dataset.action
      if (action === "audit-logs") link.href = this.searchUrl(this.auditLogsUrlValue, mac)
      if (action === "identities") link.href = this.searchUrl(this.identitiesUrlValue, mac)
      if (action === "shadow-it") link.href = this.searchUrl(this.shadowItUrlValue, mac)

      if (action === "copy") {
        link.addEventListener("click", (event) => {
          event.preventDefault()
          this.copyMac(mac, link)
        })
      }
    })
  }

  copyMac(mac, element) {
    navigator.clipboard?.writeText(mac).then(() => {
      const previous = element.textContent
      element.textContent = "Copied"
      window.setTimeout(() => {
        element.textContent = previous
      }, 1200)
    })
  }

  searchUrl(baseUrl, mac) {
    const url = new URL(baseUrl, window.location.origin)
    url.searchParams.set("q", this.searchQuery(mac))
    return url.toString()
  }

  searchQuery(mac) {
    const parts = String(mac).split(":")
    if (parts.length === 6 && parts.slice(0, 4).every((part) => /^xx$/i.test(part))) {
      return parts.slice(4).join(":")
    }

    return mac
  }

  formatTime(value) {
    if (!value) return "-"

    const date = new Date(value)
    if (Number.isNaN(date.getTime())) return "-"

    return `${date.toISOString().slice(0, 16).replace("T", " ")} UTC`
  }

  escape(value) {
    return String(value).replace(/[&<>"]/g, (char) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "\"": "&quot;"
    }[char]))
  }
}
