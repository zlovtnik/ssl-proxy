<script>
  import CommandPaletteSearch from "./CommandPaletteSearch.svelte"
  import { serializeFilters, toApiParams } from "../lib/url"

  let { fields = [], filters = [], onChange = () => {} } = $props()

  let activeFilters = $state([])
  let nextId = $state(1)

  $effect(() => {
    if (filters.length && activeFilters.length === 0) {
      activeFilters = normalizeFilters(filters)
    }
  })

  export function apiParams() {
    return toApiParams(compactFilters(activeFilters))
  }

  function normalizeFilters(nextFilters) {
    return nextFilters.map((filter) => ({
      id: filter.id || nextId++,
      field: filter.field,
      operator: filter.operator,
      value: filter.value ?? "",
      conjunction: filter.conjunction === "OR" ? "OR" : "AND"
    }))
  }

  function handleSearch(query) {
    const newFilter = {
      id: nextId++,
      field: query.field.key,
      operator: query.operator,
      value: query.value,
      conjunction: "AND"
    }
    activeFilters = [...activeFilters, newFilter]
    emit()
  }

  function removeFilter(id) {
    activeFilters = activeFilters.filter(f => f.id !== id)
    emit()
  }

  function toggleConjunction(id) {
    activeFilters = activeFilters.map(f => 
      f.id === id ? { ...f, conjunction: f.conjunction === "OR" ? "AND" : "OR" } : f
    )
    emit()
  }

  function clearAll() {
    activeFilters = []
    emit()
  }

  function compactFilters(nextFilters) {
    return nextFilters.map(({ field, operator, value, conjunction }) => ({ field, operator, value, conjunction }))
  }

  function getFieldLabel(fieldKey) {
    return fields.find(f => f.key === fieldKey)?.label || fieldKey
  }

  function emit() {
    const compacted = compactFilters(activeFilters)
    onChange(compacted, {
      serialized: serializeFilters(activeFilters),
      apiParams: toApiParams(compacted)
    })
  }
</script>

<div class="query-builder mb-4 rounded-lg border border-(--color-border-muted) bg-(--color-surface) p-3">
  <div class="mb-3">
    <CommandPaletteSearch {fields} onSearch={handleSearch} />
  </div>

  {#if activeFilters.length > 0}
    <div class="mb-2 flex items-center justify-between gap-3">
      <div class="text-xs font-semibold uppercase tracking-wide text-(--color-accent-vivid)">Active Filters</div>
      <button
        type="button"
        class="text-xs font-semibold text-(--color-text-muted) hover:text-(--color-danger-text)"
        onclick={clearAll}
      >
        Clear all
      </button>
    </div>

    <div class="flex flex-wrap gap-2">
      {#each activeFilters as filter, index (filter.id)}
        {#if index > 0}
          <button
            type="button"
            class="rounded px-2 py-1 text-xs font-semibold {filter.conjunction === 'OR' ? 'bg-orange-100 text-orange-700' : 'bg-blue-100 text-blue-700'}"
            onclick={() => toggleConjunction(filter.id)}
          >
            {filter.conjunction}
          </button>
        {/if}
        <div class="inline-flex items-center gap-2 rounded-md border border-(--color-border-muted) bg-(--color-bg) px-3 py-1.5 text-sm">
          <span class="font-semibold text-(--color-accent-vivid)">{getFieldLabel(filter.field)}</span>
          <span class="text-(--color-text-muted)">{filter.operator}</span>
          <span class="font-medium">{filter.value}</span>
          <button
            type="button"
            class="ml-1 text-lg leading-none text-(--color-danger-text) hover:text-(--color-danger-text-hover)"
            onclick={() => removeFilter(filter.id)}
          >
            ×
          </button>
        </div>
      {/each}
    </div>
  {/if}
</div>
