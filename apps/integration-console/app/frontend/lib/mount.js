import { mount, unmount } from "svelte"

const mountedPages = new Map()

export function mountPage(component, rootId) {
  mountedPages.get(rootId)?.teardown()

  let target = null
  let instance = null

  function connect() {
    const nextTarget = document.getElementById(rootId)
    if (!nextTarget) return null
    if (target === nextTarget && instance) return instance

    disconnect()

    target = nextTarget
    instance = mount(component, {
      target,
      props: readProps(rootId)
    })

    return instance
  }

  function disconnect() {
    const mounted = instance

    instance = null
    target = null

    if (mounted) unmount(mounted)
  }

  function teardown() {
    document.removeEventListener("turbo:load", connect)
    document.removeEventListener("turbo:before-cache", disconnect)
    document.removeEventListener("turbo:before-render", disconnect)
    disconnect()
    if (mountedPages.get(rootId) === controller) mountedPages.delete(rootId)
  }

  document.addEventListener("turbo:load", connect)
  document.addEventListener("turbo:before-cache", disconnect)
  document.addEventListener("turbo:before-render", disconnect)

  connect()

  const controller = {
    connect,
    disconnect,
    teardown
  }

  mountedPages.set(rootId, controller)
  return controller
}

function readProps(rootId) {
  const script = document.getElementById(`${rootId}-props`)
  if (!script) return {}

  try {
    return JSON.parse(script.textContent || "{}")
  } catch (error) {
    console.warn(`Unable to parse props for ${rootId}.`, error)
    return {}
  }
}
