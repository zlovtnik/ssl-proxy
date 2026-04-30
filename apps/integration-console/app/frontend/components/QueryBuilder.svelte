<script>
  import QueryBuilderRow from "./QueryBuilderRow.svelte"
  import { serializeFilters, toApiParams } from "../lib/url"

  export let fields = []
  export let filters = []
  export let onChange = () => {}

  let rows = []
  let nextId = 1

  $: if (rows.length === 0 && fields.length > 0) {
    rows = normalizeRows(filters.length ? filters : [blankFilter()])
    emit(false)
  }

  export function apiParams() {
    return toApiParams(compactRows(rows))
  }

  function normalizeRows(nextFilters) {
    return nextFilters.map((filter) => ({
      id: filter.id || nextId++,
      field: filter.field || fields[0]?.key || "",
      operator: filter.operator || firstOperator(filter.field || fields[0]?.key),
      value: filter.value ?? "",
      conjunction: filter.conjunction === "OR" ? "OR" : "AND"
    }))
  }

  function blankFilter() {
    return {
      id: nextId++,
      field: fields[0]?.key || "",
      operator: firstOperator(fields[0]?.key),
      value: "",
      conjunction: "AND"
    }
  }

  function firstOperator(fieldKey) {
    const field = fields.find((item) => item.key === fieldKey) || fields[0] || {}
    const operators = field.operators || []
    const operator = operators[0]
    if (typeof operator === "string") return operator
    return operator?.key || "contains"
  }

  function updateRow(index, filter) {
    rows = rows.map((row, rowIndex) => rowIndex === index ? { ...filter, id: row.id } : row)
    emit()
  }

  function addRow() {
    rows = [...rows, blankFilter()]
    emit()
  }

  function removeRow(index) {
    rows = rows.filter((_, rowIndex) => rowIndex !== index)
    if (rows.length === 0) rows = [blankFilter()]
    emit()
  }

  function toggleConjunction(index) {
    rows = rows.map((row, rowIndex) => rowIndex === index ? { ...row, conjunction: row.conjunction === "OR" ? "AND" : "OR" } : row)
    emit()
  }

  function clearAll() {
    rows = [blankFilter()]
    emit()
  }

  function compactRows(nextRows) {
    return nextRows.map(({ field, operator, value, conjunction }) => ({ field, operator, value, conjunction }))
  }

  function emit(notify = true) {
    if (!notify) return
    onChange(compactRows(rows), {
      serialized: serializeFilters(rows),
      apiParams: toApiParams(rows)
    })
  }
</script>

<div class="query-builder mb-4 rounded-lg border border-(--color-border-muted) bg-(--color-surface) p-3">
  <div class="mb-2 flex items-center justify-between gap-3">
    <div class="text-xs font-semibold uppercase tracking-wide text-(--color-accent-vivid)">Filters</div>
    <div class="sr-only" aria-live="polite">{rows.length} filter rows</div>
  </div>

  <div class="grid gap-2">
    {#each rows as row, index (row.id)}
      {#if index > 0}
        <button
          type="button"
          class={row.conjunction === "OR" ? "query-conjunction query-conjunction-or" : "query-conjunction query-conjunction-and"}
          aria-label={`Toggle conjunction before filter ${index + 1}`}
          on:click={() => toggleConjunction(index)}
        >
          {row.conjunction}
        </button>
      {/if}
      <QueryBuilderRow
        filter={row}
        {fields}
        removable={rows.length > 1}
        onChange={(filter) => updateRow(index, filter)}
        onRemove={() => removeRow(index)}
      />
    {/each}
  </div>

  <div class="mt-3 flex flex-wrap gap-2">
    <button
      type="button"
      class="min-h-9 rounded-md border border-(--color-border-strong) bg-(--color-bg) px-3 py-2 text-sm font-semibold text-(--color-accent-vivid) hover:bg-(--color-accent-surface) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
      on:click={addRow}
    >
      + Add filter
    </button>
    <button
      type="button"
      class="min-h-9 rounded-md border border-(--color-border-muted) bg-(--color-bg) px-3 py-2 text-sm font-semibold text-(--color-text-muted) hover:bg-(--color-accent-surface) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
      on:click={clearAll}
    >
      Clear all
    </button>
  </div>
</div>
