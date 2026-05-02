<script>
  import { onMount } from "svelte"

  export let initial = {}

  let alerts = []
  let endpoint = initial.endpoint || "/alerts.json"
  let initialLoadComplete = false

  onMount(() => {
    fetchAlerts()
    const handler = (e) => prepend(e.detail)
    window.addEventListener("threat-alert", handler)
    return () => window.removeEventListener("threat-alert", handler)
  })

  async function fetchAlerts() {
    const r = await fetch(endpoint, { headers: { accept: "application/json" } }).catch(() => null)
    if (!r?.ok) return
    const payload = await r.json()
    if (!initialLoadComplete) {
      alerts = payload.rows || []
      initialLoadComplete = true
    }
  }

  function prepend(data) {
    if (!data?.alert_type) return
    alerts = [data, ...alerts].slice(0, 50)
  }

  function severityClass(severity) {
    return { critical: "status-alert", warning: "status-warn" }[severity] || "muted"
  }

  function tagClass(tag) {
    if (tag?.includes("pmf_deauth") || tag?.includes("harvest")) return "status-alert"
    if (tag?.includes("karma") || tag?.includes("evil_twin")) return "status-warn"
    return "muted"
  }
</script>

<div class="panel">
  <h2>Threat Alerts</h2>
  {#if alerts.length === 0}
    <p class="empty-state">No threat alerts.</p>
  {:else}
    {#each alerts as alert}
      <div class="live-row">
        <span class={severityClass(alert.severity)}>{alert.severity}</span>
        <span class="muted"> · {alert.sensor_id}</span>
        <span> {alert.message}</span>
        {#if alert.payload?.tags}
          {#each (Array.isArray(alert.payload.tags) ? alert.payload.tags : []).filter(t => typeof t === 'string' && t.startsWith('threat:')) as tag}
            <span class={tagClass(tag)} style="margin-left:6px;font-size:11px">[{tag}]</span>
          {/each}
        {/if}
      </div>
    {/each}
  {/if}
</div>
