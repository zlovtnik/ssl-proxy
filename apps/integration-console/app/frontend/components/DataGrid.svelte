<script>
  let { 
    columns = [], 
    rows = [], 
    totalCount = 0, 
    currentPage = 1, 
    perPage = 50, 
    sortKey = "", 
    sortDirection = "desc", 
    loading = false, 
    onSort = () => {}, 
    onPageChange = () => {}, 
    rowKey = (row, index) => row.id || row.dedupe_key || row.location_id || index 
  } = $props()
  
  const paginationBtnClass = "data-grid__page-button"
  const widthPresets = {
    xs: "w-16 min-w-16",
    sm: "w-24 min-w-24",
    md: "w-32 min-w-32",
    lg: "w-40 min-w-40",
    xl: "w-56 min-w-56",
    action: "w-28 min-w-28"
  }
  const legacyWidths = {
    "w-20": "sm",
    "w-24": "sm",
    "w-28": "sm",
    "w-32": "md",
    "w-36": "md",
    "w-40": "lg",
    "w-48": "lg",
    "w-56": "xl",
    "min-w-16": "xs",
    "min-w-20": "sm",
    "min-w-24": "sm",
    "min-w-28": "sm",
    "min-w-32": "md",
    "min-w-40": "lg",
    "min-w-48": "lg"
  }

  const totalPages = $derived(Math.max(Math.ceil(Number(totalCount || 0) / Number(perPage || 1)), 1))

  function headerClasses(column) {
    return [
      "data-grid__header",
      columnWidth(column),
      hiddenClass(column.hiddenBelow)
    ].filter(Boolean).join(" ")
  }

  function cellClasses(column) {
    return [
      "data-grid__cell",
      columnWidth(column),
      hiddenClass(column.hiddenBelow)
    ].filter(Boolean).join(" ")
  }

  function columnWidth(column) {
    if (column.size && widthPresets[column.size]) return widthPresets[column.size]
    const legacySize = legacyWidths[column.width] || legacyWidths[column.minWidth]
    if (legacySize) return widthPresets[legacySize]
    return widthPresets.md
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

</script>

<div class="data-grid-wrap">
  <div class="data-grid-wrap__scroll relative">
    <table class="data-grid">
      <thead>
        <tr>
          {#each columns as column}
            <th class={headerClasses(column)} scope="col" aria-sort={sortLabel(column) || undefined} title={column.description || column.label}>
              {#if column.sortable}
                <button
                  type="button"
                  class={sortKey === column.key ? "data-grid__sort data-grid__sort--active" : "data-grid__sort"}
                  onclick={() => onSort(column.key)}
                >
                  <span class="data-grid__header-label">{column.shortLabel || column.label}</span>
                  {#if sortKey === column.key}
                    <span aria-hidden="true">{#if sortDirection === "asc"}&uarr;{:else}&darr;{/if}</span>
                  {/if}
                </button>
              {:else}
                <span class="data-grid__header-label">{column.shortLabel || column.label}</span>
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
                  {@const Component = column.component}
                  <Component value={row[column.key]} row={row} {...(column.componentProps ? column.componentProps(row[column.key], row) : {})} />
                {:else if column.href}
                  <a class="text-(--color-accent-vivid) underline-offset-2 hover:underline" href={column.href(row)}>{cellValue(column, row)}</a>
                {:else}
                  {@const value = cellValue(column, row)}
                  <span class="data-grid__cell-value" title={value || ""}>{value}</span>
                {/if}
              </td>
            {/each}
          </tr>
        {:else}
          <tr>
            <td class="data-grid__empty" colspan={columns.length}>
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

    <div class="data-grid__pagination">
      <button
        type="button"
        class={paginationBtnClass}
        disabled={currentPage <= 1 || loading}
        aria-label="Previous page"
        onclick={() => onPageChange(currentPage - 1)}
      >
        Prev
      </button>
      <span class="font-semibold">Page {currentPage} of {totalPages}</span>
      <button
        type="button"
        class={paginationBtnClass}
        disabled={currentPage >= totalPages || loading}
        aria-label="Next page"
        onclick={() => onPageChange(currentPage + 1)}
      >
        Next
      </button>
    </div>
  </div>
</div>
