import { Controller } from "@hotwired/stimulus"
import { mount, unmount } from "svelte"
import { svelteComponents } from "../svelte/registry"

export default class extends Controller {
  static values = {
    component: String,
    props: Object
  }

  connect() {
    const component = svelteComponents[this.componentValue]
    if (!component) {
      console.error(`Unknown Svelte component: ${this.componentValue}`)
      return
    }

    this.instance = mount(component, {
      target: this.element,
      props: this.propsValue || {}
    })
  }

  disconnect() {
    const instance = this.instance

    if (!instance) {
      this.element.replaceChildren()
      return
    }

    Promise.resolve(unmount(instance)).finally(() => {
      if (this.instance !== instance) return

      this.instance = null
      this.element.replaceChildren()
    })
  }
}
