export function formatTime(value) {
  if (!value) return ""

  const date = new Date(value)
  if (Number.isNaN(date.getTime())) return String(value)

  return new Intl.DateTimeFormat("en-US", {
    timeZone: "America/New_York",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
    timeZoneName: "short"
  }).format(date)
}

export function shortFingerprint(value) {
  if (!value) return ""
  return String(value).slice(0, 12)
}

export function displayBoolean(value, label = "captured") {
  return value ? label : ""
}

export function searchQueryForMac(mac) {
  const parts = String(mac || "").split(":")
  if (parts.length === 6 && parts.slice(0, 4).every((part) => /^xx$/i.test(part))) {
    return parts.slice(4).join(":")
  }

  return mac || ""
}

export function searchUrl(baseUrl, query) {
  const url = new URL(baseUrl, window.location.origin)
  url.searchParams.set("q", query)
  return url.toString()
}
