<script>
  import { onMount } from "svelte"

  export let initial = {}

  let endpoint = initial.endpoint || "/health/recent_alerts.json"
  let alerts = []
  let loading = true
  let error = ""

  onMount(fetchAlerts)

  async function fetchAlerts() {
    loading = true
    error = ""
    const response = await fetch(endpoint, { headers: { accept: "application/json" } }).catch(() => null)
    if (!response?.ok) {
      error = "Unable to load recent alerts."
      loading = false
      return
    }

    try {
      const payload = await response.json()
      alerts = payload.alerts || []
    } catch (err) {
      console.warn("Unable to parse recent alerts response.", err)
      error = "Unable to parse recent alerts response."
    } finally {
      loading = false
    }
  }
</script>

<div class="panel">
  <h2>Recent Alerts</h2>
  {#if loading}
    {#each Array(5) as _}
      <div class="relative mb-2 h-5 overflow-hidden rounded bg-(--color-border-muted)" aria-hidden="true">
        <div class="skeleton-shimmer absolute inset-0"></div>
      </div>
    {/each}
    <span class="sr-only">Loading recent alerts</span>
  {:else if error}
    <p class="status-alert">{error}</p>
  {:else if alerts.length}
    {#each alerts as alert}
      <p class={alert.statusClass}>{alert.message}</p>
    {/each}
  {:else}
    <p class="empty-state">No recent alerts found.</p>
  {/if}
</div>
