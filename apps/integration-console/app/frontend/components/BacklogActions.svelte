<script>
  export let row = {}
  export let onRetry = () => {}
  export let disabled = false
</script>

<button
  type="button"
  class="min-h-8 rounded-md border border-(--color-border-strong) bg-(--color-bg) px-2 py-1 text-sm font-semibold text-(--color-accent-vivid) hover:bg-(--color-accent-surface) disabled:cursor-not-allowed disabled:border-(--color-border-muted) disabled:text-(--color-text-faint) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
  {disabled}
  on:click={() => onRetry(row)}
>
  Retry
</button>
