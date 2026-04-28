<script>
  import { onMount } from "svelte"
  import DataGrid from "../components/DataGrid.svelte"
  import { toQueryString, updateHistory, paramsFromLocation } from "../lib/url"

  export let initial = {}

  let rows = initial.rows || []
  let visualLocations = initial.visualLocations || []
  let totalCount = initial.totalCount || 0
  let currentPage = initial.currentPage || 1
  let perPage = initial.perPage || 50
  let sortKey = initial.sortKey || "event_count"
  let sortDirection = initial.sortDirection || "desc"
  let loading = false
  const endpoints = initial.endpoints || {}

  const columns = [
    { key: "location_id", label: "Location", sortable: true, width: "w-48" },
    { key: "event_count", label: "Events", sortable: true, width: "w-32" },
    { key: "avg_signal_dbm", label: "Average Signal dBm", sortable: true, width: "w-40", format: (value) => formatSignal(value) },
    { key: "unique_devices", label: "Devices", sortable: true, width: "w-32", hiddenBelow: "md" },
    { key: "last_seen_at", label: "Last Seen", sortable: true, width: "w-40", hiddenBelow: "lg", format: (value) => value || "" }
  ]

  onMount(() => {
    const next = paramsFromLocation({ sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage })
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

  function handlePopState() {
    const next = paramsFromLocation({ sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage })
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
    visualLocations = payload.visualLocations || []
    totalCount = payload.totalCount || 0
    currentPage = payload.currentPage || currentPage
    perPage = payload.perPage || perPage
    sortKey = payload.sortKey || sortKey
    sortDirection = payload.sortDirection || sortDirection
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
    url.searchParams.set("q", location.location_id)
    return url.toString()
  }
</script>

<div>
  <h1 class="mb-4 text-2xl font-bold text-[#c8e6c8]">Logical Heatmap</h1>

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
    <h2 class="mb-3 text-lg font-semibold text-[#86efac]">Signal Strength</h2>
    <div class="grid grid-cols-1 gap-3 sm:grid-cols-2 md:grid-cols-4 lg:grid-cols-6">
      {#each visualLocations.slice(0, 200) as location}
        <a class={`group relative block rounded-lg border border-[#1f3320] p-3 text-[#0d130d] ${bucketClass(location.avg_signal_dbm)}`} href={auditUrl(location)}>
          <span class="block truncate font-semibold">{location.location_id}</span>
          <span class="block text-xs">{formatSignal(location.avg_signal_dbm)} dBm</span>
          <span class="pointer-events-none absolute left-2 right-2 top-full z-20 mt-1 hidden rounded border border-[#1f6b1f] bg-[#111a11] p-2 text-xs text-[#c8e6c8] shadow-xl group-hover:block group-focus:block">
            {location.event_count} events, {formatSignal(location.avg_signal_dbm)} dBm average
          </span>
        </a>
      {:else}
        <div class="rounded-lg border border-[#1f3320] bg-[#111a11] p-4 text-[#4d7a4d]">No heatmap data found.</div>
      {/each}
    </div>
  </section>
</div>

