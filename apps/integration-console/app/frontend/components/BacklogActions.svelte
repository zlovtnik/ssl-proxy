<script>
  export let row = {}
  export let onRetry = () => {}
  export let disabled = false
</script>

<button
  type="button"
  class="min-h-8 rounded-md border border-[var(--color-border-strong)] bg-[var(--color-bg)] px-2 py-1 text-sm font-semibold text-[var(--color-accent-vivid)] hover:bg-[var(--color-accent-surface)] disabled:cursor-not-allowed disabled:border-[var(--color-border-muted)] disabled:text-[var(--color-text-faint)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-focus)]"
  {disabled}
  on:click={() => onRetry(row)}
>
  Retry
</button>
