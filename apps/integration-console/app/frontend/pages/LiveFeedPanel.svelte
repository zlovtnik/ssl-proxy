<script>
  import LiveFeed from "../../javascript/svelte/LiveFeed.svelte"

  export let initial = {}
</script>

<div class="panel">
  <h2>Live Heads-up Stream</h2>
  <div class="mb-3 inline-flex items-center gap-2 text-sm text-(--color-text-muted)" aria-live="polite">
    <span class="h-2 w-2 animate-pulse rounded-full bg-(--color-accent-vivid)" aria-hidden="true"></span>
    Awaiting first event
  </div>
  <LiveFeed recentUrl={initial.recentUrl || "/audit_logs/recent.json"} showHeading={false} />
</div>
