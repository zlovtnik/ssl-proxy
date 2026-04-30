<script>
  import { onMount } from "svelte"

  export let initial = {}

  let endpoint = initial.endpoint || "/health/nats_samples.json"
  let rows = []
  let loading = true
  let error = ""

  onMount(fetchRows)

  async function fetchRows() {
    loading = true
    error = ""
    const response = await fetch(endpoint, { headers: { accept: "application/json" } }).catch(() => null)
    if (!response?.ok) {
      error = "Unable to load NATS throughput."
      loading = false
      return
    }

    let payload
    try {
      payload = await response.json()
    } catch (err) {
      console.warn("Unable to parse NATS throughput response.", err)
      error = "Unable to parse NATS throughput response."
      loading = false
      return
    }

    rows = payload.samples || []
    loading = false
  }
</script>

<div class="panel">
  <h2>NATS Throughput</h2>
  {#if loading}
    <div class="relative h-20 overflow-hidden rounded bg-(--color-border-muted)" aria-label="Loading NATS throughput">
      <div class="skeleton-shimmer absolute inset-0"></div>
    </div>
  {:else if error}
    <p class="status-alert">{error}</p>
  {:else if rows.length}
    {#each rows as row}
      <p><strong>{row.subject}</strong>: {row.eventCount} events in 5 minutes</p>
    {/each}
  {:else}
    <p class="empty-state">No NATS samples found.</p>
  {/if}
</div>
