<script>
  import { onMount } from "svelte"
  import DataGrid from "../components/DataGrid.svelte"
  import GridToolbar from "../components/GridToolbar.svelte"
  import { columnsToFilterFields } from "../lib/grid"
  import { serializeFilters, toQueryString, updateHistory, paramsFromLocation } from "../lib/url"

  export let initial = {}

  let rows = initial.rows || []
  let visualLocations = initial.visualLocations || []
  let totalCount = initial.totalCount || 0
  let currentPage = initial.currentPage || 1
  let perPage = initial.perPage || 50
  let sortKey = initial.sortKey || "event_count"
  let sortDirection = initial.sortDirection || "desc"
  let lastRefreshedAt = initial.lastRefreshedAt || null
  let filters = initial.filters || []
  let loading = false
  const endpoints = initial.endpoints || {}

  const columns = [
    { key: "location_id", label: "Location", sortable: true, size: "lg" },
    { key: "event_count", label: "Events", sortable: true, size: "md", filterType: "number" },
    { key: "avg_signal_dbm", label: "Average Signal dBm", shortLabel: "Avg Signal", description: "Average Signal dBm", sortable: true, size: "lg", format: (value) => formatSignal(value), filterType: "number" },
    { key: "unique_devices", label: "Devices", sortable: true, size: "md", hiddenBelow: "md", filterType: "number" },
    { key: "last_seen_at", label: "Last Seen", sortable: true, size: "lg", hiddenBelow: "lg", format: (value) => value || "", filterType: "date" }
  ]
  const filterFields = columnsToFilterFields(columns)

  onMount(() => {
    const next = paramsFromLocation({ filters, sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage })
    filters = next.filters || []
    sortKey = next.sort || "event_count"
    sortDirection = next.direction || "desc"
    currentPage = next.page
    perPage = next.per_page
    window.addEventListener("popstate", handlePopState)
    return () => window.removeEventListener("popstate", handlePopState)
  })

  function state() {
    return {
      sort: sortKey,
      filters: serializeFilters(filters) || undefined,
      direction: sortDirection,
      page: currentPage,
      per_page: perPage
    }
  }

  function handleSort(key) {
    sortDirection = sortKey === key && sortDirection === "asc" ? "desc" : "asc"
    sortKey = key
    currentPage = 1
    fetchPage(true)
  }

  function handlePageChange(page) {
    currentPage = page
    fetchPage(true)
  }

  function handleFiltersChange(nextFilters) {
    filters = nextFilters
    currentPage = 1
    fetchPage(true)
  }

  function handlePopState() {
    const next = paramsFromLocation({ filters, sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage })
    filters = next.filters || []
    sortKey = next.sort || "event_count"
    sortDirection = next.direction || "desc"
    currentPage = next.page
    perPage = next.per_page
    fetchPage(false)
  }

  async function fetchPage(push) {
    if (!endpoints.index) return

    loading = true
    if (push) updateHistory(endpoints.index, state())

    const response = await fetch(`${endpoints.index}.json?${toQueryString(state())}`, { headers: { accept: "application/json" } }).catch(() => null)
    loading = false
    if (!response?.ok) return

    const payload = await response.json()
    rows = payload.rows || []
    filters = payload.filters || filters
    visualLocations = payload.visualLocations || []
    totalCount = payload.totalCount || 0
    currentPage = payload.currentPage || currentPage
    perPage = payload.perPage || perPage
    sortKey = payload.sortKey || sortKey
    sortDirection = payload.sortDirection || sortDirection
    lastRefreshedAt = payload.lastRefreshedAt || lastRefreshedAt
  }

  function formatSignal(value) {
    const number = Number.parseFloat(value)
    return Number.isFinite(number) ? number.toFixed(1) : ""
  }

  function bucketClass(dbm) {
    const clamped = Math.max(-90, Math.min(-30, Number.isFinite(Number(dbm)) ? Number(dbm) : -90))
    const bucket = Math.max(0, Math.min(9, Math.round(((clamped + 90) / 60) * 9)))
    return `signal-bucket-${bucket}`
  }

  function auditUrl(location) {
    const url = new URL("/audit_logs", window.location.origin)
    url.searchParams.set("location_id", location.location_id)
    return url.toString()
  }
</script>

<div>
  <h1 class="mb-4 text-2xl font-bold text-(--color-text)">Logical Heatmap</h1>
  {#if lastRefreshedAt}
    <p class="mb-3 text-sm text-(--color-text-muted)">Last refreshed: {lastRefreshedAt}</p>
  {/if}

  <GridToolbar
    query=""
    {filters}
    fields={filterFields}
    searchable={false}
    onSearch={() => {}}
    onFiltersChange={handleFiltersChange}
  />

  <DataGrid
    {columns}
    {rows}
    {totalCount}
    {currentPage}
    {perPage}
    {sortKey}
    {sortDirection}
    {loading}
    onSort={handleSort}
    onPageChange={handlePageChange}
    rowKey={(row) => row.location_id}
  />

  <section class="mt-5">
    <h2 class="mb-3 text-lg font-semibold text-(--color-accent-vivid)">Signal Strength</h2>
    <div class="grid grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-6">
      {#each visualLocations.slice(0, 200) as location}
        <a class={`group relative block rounded-lg border border-(--color-border-muted) p-3 ${bucketClass(location.avg_signal_dbm)}`} href={auditUrl(location)}>
          <span class="block truncate font-semibold">{location.location_id}</span>
          <span class="block text-xs">{formatSignal(location.avg_signal_dbm)} dBm</span>
          <span class="pointer-events-none absolute left-2 right-2 top-full z-20 mt-1 hidden rounded border border-(--color-border-strong) bg-(--color-surface) p-2 text-xs text-(--color-text) shadow-xl group-hover:block group-focus:block">
            {location.event_count} events, {formatSignal(location.avg_signal_dbm)} dBm average
          </span>
        </a>
      {:else}
        <div class="rounded-lg border border-(--color-border-muted) bg-(--color-surface) p-4 text-(--color-text-faint)">No heatmap data found.</div>
      {/each}
    </div>
  </section>
</div>
