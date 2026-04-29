import { mount } from "svelte"

export function mountPage(component, rootId) {
  const target = document.getElementById(rootId)
  if (!target) return null

  const props = readProps(rootId)
  return mount(component, { target, props })
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

