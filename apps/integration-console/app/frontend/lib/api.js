export function csrfToken() {
  return document.querySelector("meta[name='csrf-token']")?.content || ""
}

export async function requestJson(url, { method = "GET", body = undefined } = {}) {
  const headers = { accept: "application/json" }
  const options = { method, headers }

  if (method !== "GET") headers["X-CSRF-Token"] = csrfToken()
  if (body !== undefined) {
    headers["Content-Type"] = "application/json"
    options.body = JSON.stringify(body)
  }

  const response = await fetch(url, options)
  const text = await response.text()
  const payload = text ? parseJson(text) : null

  if (!response.ok) {
    const error = new Error(errorMessage(payload) || "Request failed.")
    error.status = response.status
    error.payload = payload
    throw error
  }

  return payload
}

export function errorMessages(error) {
  if (Array.isArray(error?.payload?.errors)) return error.payload.errors
  if (error?.payload?.error) return [error.payload.error]
  if (error?.message) return [error.message]
  return ["Request failed."]
}

function parseJson(text) {
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

function errorMessage(payload) {
  if (payload?.error) return payload.error
  if (Array.isArray(payload?.errors)) return payload.errors.join(", ")
  return null
}
