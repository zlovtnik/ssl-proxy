const prefersReducedMotion = () => window.matchMedia("(prefers-reduced-motion: reduce)").matches

document.addEventListener("turbo:morph-element", (event) => {
  if (prefersReducedMotion()) return
  if (!(event.target instanceof HTMLElement)) return
  if (event.target.dataset.animateMorph !== "true") return

  event.target.classList.add("turbo-morph-highlight")
  window.setTimeout(() => {
    event.target.classList.remove("turbo-morph-highlight")
  }, 260)
})
