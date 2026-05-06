<script>
  import { onDestroy } from "svelte"
  import QueryBuilder from "./QueryBuilder.svelte"

  export let query = ""
  export let filters = []
  export let fields = []
  export let searchable = true
  export let placeholder = "Search"
  export let label = "Search"
  export let debounceMs = 350
  export let onSearch = () => {}
  export let onFiltersChange = () => {}
  export let onClearAll = null
  export let onFetchValues = null

  let timer = null

  $: hasFilters = fields.length > 0
  $: hasQuery = query.trim().length > 0
  $: hasActiveFilters = filters.length > 0

  function scheduleSearch() {
    window.clearTimeout(timer)
    timer = window.setTimeout(() => onSearch({ q: query }), debounceMs)
  }

  function clearAll() {
    window.clearTimeout(timer)
    query = ""
    if (onClearAll) {
      onClearAll()
    } else if (searchable) {
      onSearch({ q: "" })
    } else {
      onFiltersChange([], { serialized: "", apiParams: {} })
    }
  }

  onDestroy(() => {
    window.clearTimeout(timer)
  })
</script>

<section class="grid-toolbar" aria-label="Grid controls">
  <div class="grid-toolbar__row">
    {#if searchable}
      <label class="grid-toolbar__search">
        <span>{label}</span>
        <input
          class="grid-toolbar__input"
          type="search"
          bind:value={query}
          {placeholder}
          on:input={scheduleSearch}
        />
      </label>
    {/if}

    <button
      type="button"
      class="grid-toolbar__clear"
      disabled={!hasQuery && !hasActiveFilters}
      on:click={clearAll}
    >
      Clear
    </button>

    <slot name="controls" />
  </div>

  {#if hasFilters}
    <QueryBuilder {fields} {filters} onChange={onFiltersChange} {onFetchValues} />
  {/if}
</section>
