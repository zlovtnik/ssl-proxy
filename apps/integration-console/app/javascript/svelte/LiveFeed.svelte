<script>
  import { onMount } from "svelte"
  import { flip } from "svelte/animate"
  import { fade, fly } from "svelte/transition"

  export let recentUrl = ""
  export let showHeading = true
  export let onRowsChange = () => {}

  let rows = []
  let seen = new Set()
  let lastObservedAt = null
  let transitionsEnabled = false

  onMount(() => {
    transitionsEnabled = !window.matchMedia("(prefers-reduced-motion: reduce)").matches

    const handleAudit = (event) => prepend(event.detail)
    const pollTimer = window.setInterval(fetchRecent, 10000)

    window.addEventListener("live-audit", handleAudit)
    fetchRecent()

    return () => {
      window.removeEventListener("live-audit", handleAudit)
      window.clearInterval(pollTimer)
    }
  })

  async function fetchRecent() {
    if (!recentUrl) return

    const url = new URL(recentUrl, window.location.origin)
    if (lastObservedAt) url.searchParams.set("after", lastObservedAt)
    url.searchParams.set("limit", "25")

    const response = await fetch(url, { headers: { accept: "application/json" } }).catch(() => null)
    if (!response?.ok) return

    let recentRows
    try {
      recentRows = await response.json()
    } catch (error) {
      console.warn("Unable to parse recent audit rows.", error)
      return
    }

    if (!Array.isArray(recentRows)) return

    recentRows.reverse().forEach((row) => prepend(row))
  }

  function prepend(data) {
    if (!data) return

    const key = rowKey(data)
    if (key && seen.has(key)) return
    const row = {
      key,
      text: `${data.observed_at || ""} ${data.sensor_id || "unknown"} ${data.frame_subtype || data.event_type || "event"} ${data.ssid || ""}`
    }

    replaceRows([row, ...rows].slice(0, 25))

    if (data.observed_at && (!lastObservedAt || data.observed_at > lastObservedAt)) {
      lastObservedAt = data.observed_at
    }
  }

  function replaceRows(nextRows) {
    rows = nextRows
    seen = new Set(rows.map((row) => row.key).filter(Boolean))
    onRowsChange(rows)
  }

  function rowKey(data) {
    return data.dedupe_key || [
      data.observed_at,
      data.sensor_id,
      data.frame_subtype || data.event_type,
      data.source_mac,
      data.ssid
    ].join("|")
  }
</script>

{#if showHeading}
  <h2>Live Heads-up Stream</h2>
{/if}
<div role="log" aria-live="polite" aria-relevant="additions text">
  <ul class="live-feed-list">
    {#each rows as row (row.key)}
      <li
        class="live-row"
        animate:flip={transitionsEnabled ? { duration: 160 } : { duration: 0 }}
        in:fly={transitionsEnabled ? { y: -4, duration: 160 } : { y: 0, duration: 0 }}
        out:fade={transitionsEnabled ? { duration: 120 } : { duration: 0 }}
      >
        {row.text}
      </li>
    {:else}
      <li class="live-row live-row-empty">Waiting for audit events.</li>
    {/each}
  </ul>
</div>
