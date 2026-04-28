let focusMainAfterRender = false

document.addEventListener("turbo:before-render", () => {
  focusMainAfterRender = true
})

document.addEventListener("turbo:load", () => {
  if (!focusMainAfterRender) return

  const main = document.getElementById("main-content")
  if (main) {
    main.focus({ preventScroll: true })
  }

  focusMainAfterRender = false
})
