<script>
  import QueryBuilder from "./QueryBuilder.svelte"

  export let columns = []
  export let rows = []
  export let totalCount = 0
  export let currentPage = 1
  export let perPage = 50
  export let sortKey = ""
  export let sortDirection = "desc"
  export let loading = false
  export let filters = []
  export let filterFields = []
  export let onSort = () => {}
  export let onPageChange = () => {}
  export let onFiltersChange = () => {}
  export let rowKey = (row, index) => row.id || row.dedupe_key || row.location_id || index
  const paginationBtnClass = "rounded-md border border-(--color-border-strong) bg-(--color-surface) px-3 py-2 font-semibold text-(--color-accent-vivid) disabled:cursor-not-allowed disabled:border-(--color-border-muted) disabled:text-(--color-text-faint)"

  $: totalPages = Math.max(Math.ceil(Number(totalCount || 0) / Number(perPage || 1)), 1)
  $: gridFilterFields = filterFields.length ? filterFields : columnsToFilterFields(columns)

  function headerClasses(column) {
    return [
      "sticky top-0 z-10 border-b-2 border-(--color-border-strong) bg-(--color-accent-surface) px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-(--color-accent-vivid)",
      column.minWidth || "",
      hiddenClass(column.hiddenBelow)
    ].filter(Boolean).join(" ")
  }

  function cellClasses(column) {
    return [
      "border-b border-(--color-border-muted) px-3 py-2 align-top text-sm text-(--color-text)",
      column.minWidth || "",
      hiddenClass(column.hiddenBelow)
    ].filter(Boolean).join(" ")
  }

  function hiddenClass(breakpoint) {
    if (breakpoint === "sm") return "hidden sm:table-cell"
    if (breakpoint === "md") return "hidden md:table-cell"
    if (breakpoint === "lg") return "hidden lg:table-cell"
    return ""
  }

  function sortLabel(column) {
    if (sortKey !== column.key) return ""
    return sortDirection === "asc" ? "ascending" : "descending"
  }

  function cellValue(column, row) {
    const value = row[column.key]
    return column.format ? column.format(value, row) : value
  }

  function columnsToFilterFields(nextColumns) {
    return nextColumns
      .filter((column) => column.key && !column.key.startsWith("__"))
      .map((column) => ({
        key: column.filterKey || column.key,
        label: column.label || column.key,
        type: column.filterType || "text",
        options: column.filterOptions
      }))
  }
</script>

<div>
  {#if gridFilterFields.length}
    <QueryBuilder fields={gridFilterFields} {filters} onChange={onFiltersChange} />
  {/if}

  <div class="relative overflow-x-auto rounded-lg border border-(--color-border-muted) bg-(--color-surface)">
    <table class="min-w-full table-auto border-collapse">
      <thead>
        <tr>
          {#each columns as column}
            <th class={headerClasses(column)} scope="col" aria-sort={sortLabel(column) || undefined}>
              {#if column.sortable}
                <button
                  type="button"
                  class={[
                    "inline-flex w-full items-center gap-1 text-left text-xs font-semibold uppercase tracking-wide hover:text-(--color-accent-vivid) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)",
                    sortKey === column.key ? "text-(--color-accent-vivid) underline" : "text-(--color-accent-text)"
                  ].join(" ")}
                  on:click={() => onSort(column.key)}
                >
                  <span class="truncate">{column.label}</span>
                  {#if sortKey === column.key}
                    <span aria-hidden="true">{#if sortDirection === "asc"}&uarr;{:else}&darr;{/if}</span>
                  {/if}
                </button>
              {:else}
                {column.label}
              {/if}
            </th>
          {/each}
        </tr>
      </thead>
      <tbody class={loading ? "opacity-60" : ""}>
        {#each rows as row, index (rowKey(row, index))}
          <tr class={row.__new ? "row-new hover:bg-(--color-accent-surface)" : "hover:bg-(--color-accent-surface)"}>
            {#each columns as column}
              <td class={cellClasses(column)}>
                {#if column.component}
                  <svelte:component this={column.component} value={row[column.key]} row={row} {...(column.componentProps ? column.componentProps(row[column.key], row) : {})} />
                {:else if column.href}
                  <a class="text-(--color-accent-vivid) underline-offset-2 hover:underline" href={column.href(row)}>{cellValue(column, row)}</a>
                {:else}
                  <span class="block truncate" title={cellValue(column, row) || ""}>{cellValue(column, row)}</span>
                {/if}
              </td>
            {/each}
          </tr>
        {:else}
          <tr>
            <td class="border-b border-(--color-border-muted) px-3 py-8 text-center text-sm text-(--color-text-faint)" colspan={columns.length}>
              No rows found.
            </td>
          </tr>
        {/each}
      </tbody>
    </table>

    {#if loading}
      <div class="pointer-events-none absolute inset-x-0 top-10 bottom-12 overflow-hidden bg-(--color-surface-scrim)" aria-hidden="true">
        <div class="skeleton-shimmer h-full"></div>
      </div>
    {/if}

    <div class="flex items-center gap-3 border-t border-(--color-border-muted) bg-(--color-bg) px-3 py-3 text-sm text-(--color-text-muted)">
      <button
        type="button"
        class={paginationBtnClass}
        disabled={currentPage <= 1 || loading}
        aria-label="Previous page"
        on:click={() => onPageChange(currentPage - 1)}
      >
        Prev
      </button>
      <span class="font-semibold">Page {currentPage} of {totalPages}</span>
      <button
        type="button"
        class={paginationBtnClass}
        disabled={currentPage >= totalPages || loading}
        aria-label="Next page"
        on:click={() => onPageChange(currentPage + 1)}
      >
        Next
      </button>
    </div>
  </div>
</div>
