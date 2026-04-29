<script>
  export let columns = []
  export let rows = []
  export let totalCount = 0
  export let currentPage = 1
  export let perPage = 50
  export let sortKey = ""
  export let sortDirection = "desc"
  export let loading = false
  export let onSort = () => {}
  export let onPageChange = () => {}
  export let rowKey = (row, index) => row.id || row.dedupe_key || row.location_id || index

  $: totalPages = Math.max(Math.ceil(Number(totalCount || 0) / Number(perPage || 1)), 1)

  function headerClasses(column) {
    return [
      "sticky top-0 z-10 border-b-2 border-[#1f6b1f] bg-[#0f2d0f] px-3 py-2 text-left text-xs font-semibold uppercase tracking-wide text-[#86efac]",
      column.width || "",
      hiddenClass(column.hiddenBelow)
    ].filter(Boolean).join(" ")
  }

  function cellClasses(column) {
    return [
      "border-b border-[#1a2e1a] px-3 py-2 align-top text-sm text-[#c8e6c8]",
      column.width || "",
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
</script>

<div class="relative overflow-x-auto rounded-lg border border-[#1f3320] bg-[#111a11]">
  <table class="min-w-full table-fixed border-collapse">
    <thead>
      <tr>
        {#each columns as column}
          <th class={headerClasses(column)} scope="col" aria-sort={sortLabel(column) || undefined}>
            {#if column.sortable}
              <button
                type="button"
                class={[
                  "inline-flex w-full items-center gap-1 text-left text-xs font-semibold uppercase tracking-wide hover:text-[#4ade80] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#fbbf24]",
                  sortKey === column.key ? "text-[#4ade80] underline" : "text-[#86efac]"
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
        <tr class={row.__new ? "row-new hover:bg-[#0f2d0f]" : "hover:bg-[#0f2d0f]"}>
          {#each columns as column}
            <td class={cellClasses(column)}>
              {#if column.component}
                <svelte:component this={column.component} value={row[column.key]} row={row} {...(column.componentProps ? column.componentProps(row[column.key], row) : {})} />
              {:else if column.href}
                <a class="text-[#86efac] underline-offset-2 hover:underline" href={column.href(row)}>{cellValue(column, row)}</a>
              {:else}
                <span class="block truncate" title={cellValue(column, row) || ""}>{cellValue(column, row)}</span>
              {/if}
            </td>
          {/each}
        </tr>
      {:else}
        <tr>
          <td class="border-b border-[#1a2e1a] px-3 py-8 text-center text-sm text-[#4d7a4d]" colspan={columns.length}>
            No rows found.
          </td>
        </tr>
      {/each}
    </tbody>
  </table>

  {#if loading}
    <div class="pointer-events-none absolute inset-x-0 top-10 bottom-12 overflow-hidden bg-[#111a11]/55" aria-hidden="true">
      <div class="skeleton-shimmer h-full"></div>
    </div>
  {/if}

  <div class="flex items-center gap-3 border-t border-[#1f3320] bg-[#0d130d] px-3 py-3 text-sm text-[#6b9e6b]">
    <button
      type="button"
      class="rounded-md border border-[#1f6b1f] bg-[#111a11] px-3 py-2 font-semibold text-[#86efac] disabled:cursor-not-allowed disabled:border-[#1f3320] disabled:text-[#4d7a4d]"
      disabled={currentPage <= 1 || loading}
      aria-label="Previous page"
      on:click={() => onPageChange(currentPage - 1)}
    >
      Prev
    </button>
    <span class="font-semibold">Page {currentPage} of {totalPages}</span>
    <button
      type="button"
      class="rounded-md border border-[#1f6b1f] bg-[#111a11] px-3 py-2 font-semibold text-[#86efac] disabled:cursor-not-allowed disabled:border-[#1f3320] disabled:text-[#4d7a4d]"
      disabled={currentPage >= totalPages || loading}
      aria-label="Next page"
      on:click={() => onPageChange(currentPage + 1)}
    >
      Next
    </button>
  </div>
</div>
