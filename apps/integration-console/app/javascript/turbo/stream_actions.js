import { StreamActions } from "@hotwired/turbo"

const MOTION_MS = 180

const prefersReducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches

const animateIn = (element) => {
  if (prefersReducedMotion() || !(element instanceof HTMLElement)) return

  element.classList.add("turbo-stream-enter")
  requestAnimationFrame(() => {
    element.classList.add("turbo-stream-enter-active")
  })

  window.setTimeout(() => {
    element.classList.remove("turbo-stream-enter", "turbo-stream-enter-active")
  }, MOTION_MS)
}

const animateOut = (element) => {
  if (prefersReducedMotion() || !(element instanceof HTMLElement)) {
    element.remove()
    return
  }

  element.classList.add("turbo-stream-leave")
  requestAnimationFrame(() => {
    element.classList.add("turbo-stream-leave-active")
  })

  window.setTimeout(() => {
    element.remove()
  }, MOTION_MS)
}

StreamActions.animated_append = function () {
  this.targetElements.forEach((target) => {
    const fragment = this.templateContent.cloneNode(true)
    const inserted = Array.from(fragment.children)

    target.append(fragment)
    inserted.forEach((element) => animateIn(element))
  })
}

StreamActions.animated_remove = function () {
  this.targetElements.forEach((element) => animateOut(element))
}
