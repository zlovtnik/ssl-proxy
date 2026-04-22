import { Controller } from "@hotwired/stimulus"

const STORAGE_KEY = "integration-console.sidebar.open"

export default class extends Controller {
  static targets = ["panel", "toggle"]

  connect() {
    const stored = window.localStorage.getItem(STORAGE_KEY)
    const defaultOpen = window.matchMedia("(min-width: 900px)").matches
    this.setOpen(stored === null ? defaultOpen : stored === "true")
  }

  toggle() {
    this.setOpen(!this.isOpen)
  }

  close() {
    this.setOpen(false)
  }

  setOpen(open) {
    this.isOpen = open
    this.element.classList.toggle("sidebar-open", open)
    this.panelTarget.classList.toggle("is-open", open)
    this.toggleTarget.setAttribute("aria-expanded", String(open))
    window.localStorage.setItem(STORAGE_KEY, String(open))
  }
}
