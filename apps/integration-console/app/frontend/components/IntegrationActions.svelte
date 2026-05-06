<script>
  export let row = {}
  export let onTrigger = () => {}
  export let onDisable = () => {}
</script>

<div class="flex flex-wrap gap-2">
  <a class="text-(--color-accent-vivid) underline-offset-2 hover:underline" href={row.show_url}>Open</a>
  <button type="button" class="text-(--color-accent-vivid) underline-offset-2 hover:underline" on:click={() => onTrigger(row)}>Trigger</button>
  {#if row.enabled}
    <button type="button" class="text-(--color-danger-text) underline-offset-2 hover:underline" on:click={() => onDisable(row)}>Disable</button>
  {/if}
</div>
