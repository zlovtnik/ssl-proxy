<script>
  export let row = {}
  export let onTrigger = () => {}
  export let onDisable = () => {}
</script>

<div class="flex flex-wrap gap-2">
  <a class="text-(--color-accent-vivid) underline-offset-2 hover:underline focus:underline" href={row.show_url} aria-label={`Open integration ${row.name || "integration"}`}>Open</a>
  <button type="button" class="text-(--color-accent-vivid) underline-offset-2 hover:underline focus:underline" on:click={() => onTrigger(row)} aria-label={`Trigger integration ${row.name || "integration"}`}>Trigger</button>
  {#if row.enabled}
    <button type="button" class="text-(--color-danger-text) underline-offset-2 hover:underline focus:underline" on:click={() => onDisable(row)} aria-label={`Disable integration ${row.name || "integration"}`}>Disable</button>
  {/if}
</div>
