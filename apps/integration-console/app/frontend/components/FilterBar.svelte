<script>
  import { onDestroy } from "svelte"
  import Select from "./Select.svelte"

  export let query = ""
  export let filters = []
  export let onSearch = () => {}
  export let debounceMs = 350
  export let placeholder = "Search sensor, MAC, SSID, username, fingerprint, WPS"

  let values = {}
  let timer = null

  $: syncDefaults(filters)

  function syncDefaults(nextFilters) {
    nextFilters.forEach((filter) => {
      if (values[filter.key] !== undefined) return
      values[filter.key] = filter.type === "checkbox" ? false : ""
      if (filter.type === "daterange") {
        values[`${filter.key}_from`] = ""
        values[`${filter.key}_to`] = ""
      }
    })
  }

  function scheduleSearch() {
    window.clearTimeout(timer)
    timer = window.setTimeout(() => onSearch(params()), debounceMs)
  }

  function searchNow() {
    window.clearTimeout(timer)
    onSearch(params())
  }

  function params() {
    const next = { q: query }

    filters.forEach((filter) => {
      if (filter.type === "daterange") {
        next[`${filter.key}_from`] = values[`${filter.key}_from`] || undefined
        next[`${filter.key}_to`] = values[`${filter.key}_to`] || undefined
        return
      }

      next[filter.key] = values[filter.key] || undefined
    })

    return next
  }

  function clearFilters() {
    query = ""
    filters.forEach((filter) => {
      values[filter.key] = filter.type === "checkbox" ? false : ""
      if (filter.type === "daterange") {
        values[`${filter.key}_from`] = ""
        values[`${filter.key}_to`] = ""
      }
    })
    values = { ...values }
    searchNow()
  }

  onDestroy(() => {
    window.clearTimeout(timer)
  })
</script>

<div class="mb-4 flex flex-wrap items-end gap-3 rounded-lg border border-[var(--color-border-muted)] bg-[var(--color-surface)] p-3">
  <label class="grid min-w-64 flex-1 gap-1 text-xs font-semibold uppercase tracking-wide text-[var(--color-accent-vivid)]">
    <span>Search</span>
    <input
      class="min-h-9 rounded-md border border-[var(--color-control-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-faint)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-focus)]"
      type="search"
      bind:value={query}
      {placeholder}
      on:input={scheduleSearch}
    />
  </label>

  {#each filters as filter}
    {#if filter.type === "select"}
      <Select label={filter.label} bind:value={values[filter.key]} options={filter.options || []} onChange={searchNow} />
    {:else if filter.type === "text"}
      <label class="grid gap-1 text-xs font-semibold uppercase tracking-wide text-[var(--color-accent-vivid)]">
        <span>{filter.label}</span>
        <input
          class="min-h-9 rounded-md border border-[var(--color-control-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-focus)]"
          type="text"
          bind:value={values[filter.key]}
          on:input={scheduleSearch}
        />
      </label>
    {:else if filter.type === "checkbox"}
      <label class="inline-flex min-h-9 items-center gap-2 rounded-md border border-[var(--color-control-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text)]">
        <input type="checkbox" bind:checked={values[filter.key]} on:change={searchNow} />
        <span>{filter.label}</span>
      </label>
    {:else if filter.type === "daterange"}
      <fieldset class="grid gap-1 text-xs font-semibold uppercase tracking-wide text-[var(--color-accent-vivid)]">
        <legend>{filter.label}</legend>
        <div class="flex gap-2">
          <input
            class="min-h-9 rounded-md border border-[var(--color-control-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-focus)]"
            type="date"
            max={values[`${filter.key}_to`] || undefined}
            bind:value={values[`${filter.key}_from`]}
            on:change={searchNow}
          />
          <input
            class="min-h-9 rounded-md border border-[var(--color-control-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-focus)]"
            type="date"
            min={values[`${filter.key}_from`] || undefined}
            bind:value={values[`${filter.key}_to`]}
            on:change={searchNow}
          />
        </div>
      </fieldset>
    {/if}
  {/each}

  <button
    type="button"
    class="min-h-9 rounded-md border border-[var(--color-border-strong)] bg-[var(--color-bg)] px-3 py-2 text-sm font-semibold text-[var(--color-accent-vivid)] hover:bg-[var(--color-accent-surface)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-focus)]"
    on:click={clearFilters}
  >
    Clear filters
  </button>
</div>
