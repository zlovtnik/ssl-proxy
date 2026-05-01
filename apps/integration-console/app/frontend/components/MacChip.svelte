<script>
  import { onDestroy } from "svelte"
  import MacHoverCard from "./MacHoverCard.svelte"
  import { searchQueryForMac, searchUrl } from "../lib/format"

  export let mac = ""
  export let display = ""
  export let masked = true
  export let auditLogsUrl = ""
  export let identitiesUrl = ""
  export let shadowItUrl = ""
  export let inventoryUrl = ""
  export let summaryUrl = ""
  export let recentAuditLogsUrl = ""

  let open = false
  let hideTimer = null
  let showTimer = null
  let anchor

  $: shown = display || (masked ? maskMac(mac) : mac)
  $: href = searchUrl(auditLogsUrl || window.location.pathname, searchQueryForMac(shown || mac))

  function maskMac(value) {
    if (!value) return ""
    const parts = String(value).split(":")
    if (parts.length !== 6) return "masked"
    return `XX:XX:XX:XX:${parts[4]}:${parts[5]}`
  }

  function scheduleShow() {
    window.clearTimeout(hideTimer)
    window.clearTimeout(showTimer)
    showTimer = window.setTimeout(() => {
      open = true
    }, 2000)
  }

  function showNow() {
    window.clearTimeout(hideTimer)
    window.clearTimeout(showTimer)
    open = true
  }

  function scheduleHide() {
    window.clearTimeout(showTimer)
    window.clearTimeout(hideTimer)
    hideTimer = window.setTimeout(() => {
      open = false
    }, 180)
  }

  onDestroy(() => {
    window.clearTimeout(hideTimer)
    window.clearTimeout(showTimer)
    hideTimer = null
    showTimer = null
  })
</script>

{#if mac || shown}
  <span class="relative inline-flex" role="presentation" on:mouseenter={scheduleShow} on:mouseleave={scheduleHide} on:focusin={showNow} on:focusout={scheduleHide}>
    <a
      bind:this={anchor}
      class="inline-flex items-center gap-1 whitespace-nowrap rounded-md border border-(--color-border-strong) bg-(--color-accent-surface) px-2 py-0.5 font-mono text-xs text-(--color-accent-vivid) no-underline hover:bg-(--color-accent-surface-strong) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
      {href}
      aria-label={`Search for MAC ${shown || mac}`}
    >
      <span class="h-1.5 w-1.5 shrink-0 rounded-full bg-(--color-accent)" aria-hidden="true"></span>
      <span>{shown || mac}</span>
    </a>
    <MacHoverCard
      {mac}
      {anchor}
      {open}
      {auditLogsUrl}
      {identitiesUrl}
      {shadowItUrl}
      {inventoryUrl}
      {summaryUrl}
      {recentAuditLogsUrl}
      onDismiss={() => (open = false)}
    />
  </span>
{/if}
