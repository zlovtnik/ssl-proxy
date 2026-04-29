<script>
  export let label = ""
  export let value = ""
  export let options = []
  export let onChange = () => {}
</script>

<label class="grid gap-1 text-xs font-semibold uppercase tracking-wide text-(--color-accent-vivid)">
  <span>{label}</span>
  <span class="relative">
    <select
      class="min-h-9 w-full appearance-none rounded-md border border-(--color-control-border) bg-(--color-surface) px-3 py-2 pr-8 text-sm text-(--color-text) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
      bind:value
      on:change={() => onChange(value)}
    >
      <option value="">Any</option>
      {#each options as option}
        <option value={option.value}>{option.label}</option>
      {/each}
    </select>
    <svg class="pointer-events-none absolute right-2 top-1/2 h-4 w-4 -translate-y-1/2 text-(--color-accent-vivid)" viewBox="0 0 24 24" aria-hidden="true">
      <path d="m6 9 6 6 6-6" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
    </svg>
  </span>
</label>

