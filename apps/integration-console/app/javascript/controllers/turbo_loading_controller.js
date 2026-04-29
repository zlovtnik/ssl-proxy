import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  connect() {
    this.pendingRequests = 0
    this.beforeVisit = () => this.start()
    this.beforeFetchRequest = (event) => {
      if (this.isPrefetch(event)) return

      this.start()
    }
    this.beforeFetchResponse = () => this.finish()
    this.fetchRequestError = () => this.finish()
    this.submitStart = () => this.start()
    this.submitEnd = () => this.finish()
    this.load = () => this.finishAll()

    document.addEventListener("turbo:before-visit", this.beforeVisit)
    document.addEventListener("turbo:before-fetch-request", this.beforeFetchRequest)
    document.addEventListener("turbo:before-fetch-response", this.beforeFetchResponse)
    document.addEventListener("turbo:fetch-request-error", this.fetchRequestError)
    document.addEventListener("turbo:submit-start", this.submitStart)
    document.addEventListener("turbo:submit-end", this.submitEnd)
    document.addEventListener("turbo:load", this.load)
  }

  disconnect() {
    document.removeEventListener("turbo:before-visit", this.beforeVisit)
    document.removeEventListener("turbo:before-fetch-request", this.beforeFetchRequest)
    document.removeEventListener("turbo:before-fetch-response", this.beforeFetchResponse)
    document.removeEventListener("turbo:fetch-request-error", this.fetchRequestError)
    document.removeEventListener("turbo:submit-start", this.submitStart)
    document.removeEventListener("turbo:submit-end", this.submitEnd)
    document.removeEventListener("turbo:load", this.load)
  }

  start() {
    this.pendingRequests += 1
    document.body.classList.add("is-turbo-loading")
    document.body.setAttribute("aria-busy", "true")
  }

  finish() {
    this.pendingRequests = Math.max(0, this.pendingRequests - 1)
    if (this.pendingRequests === 0) {
      document.body.classList.remove("is-turbo-loading")
      document.body.removeAttribute("aria-busy")
    }
  }

  finishAll() {
    this.pendingRequests = 0
    document.body.classList.remove("is-turbo-loading")
    document.body.removeAttribute("aria-busy")
  }

  isPrefetch(event) {
    const headers = event.detail.fetchOptions.headers
    if (headers instanceof Headers) return headers.get("X-Sec-Purpose") === "prefetch"

    return headers?.["X-Sec-Purpose"] === "prefetch"
  }
}
