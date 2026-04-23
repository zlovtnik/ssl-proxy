import { Controller } from "@hotwired/stimulus"

export default class extends Controller {
  connect() {
    this.beforeVisit = () => document.body.classList.add("is-turbo-loading")
    this.load = () => document.body.classList.remove("is-turbo-loading")
    document.addEventListener("turbo:before-visit", this.beforeVisit)
    document.addEventListener("turbo:load", this.load)
  }

  disconnect() {
    document.removeEventListener("turbo:before-visit", this.beforeVisit)
    document.removeEventListener("turbo:load", this.load)
  }
}
