<script>
  import { onDestroy, onMount } from "svelte"
  import DataGrid from "../components/DataGrid.svelte"
  import GridToolbar from "../components/GridToolbar.svelte"
  import { buildAuditLogColumns } from "../config/auditLogColumns"
  import { columnsToFilterFields } from "../lib/grid"
  import { paramsFromLocation, serializeFilters, toQueryString, updateHistory } from "../lib/url"

  export let initial = {}

  let rows = initial.rows || []
  let totalCount = initial.totalCount || 0
  let currentPage = initial.currentPage || 1
  let perPage = initial.perPage || 50
  let sortKey = initial.sortKey || "observed_at"
  let sortDirection = initial.sortDirection || "desc"
  let query = initial.query || ""
  let locationId = initial.locationId || ""
  let filters = initial.filters || []
  let loading = false
  let loadError = ""
  let lastObservedAt = latestObservedAt(rows)
  let pollTimer = null

  const endpoints = initial.endpoints || {}
  const macOptions = initial.macOptions || {}
  const fullMacs = Boolean(initial.fullMacs)
  const columns = buildAuditLogColumns({ endpoints, macOptions, fullMacs })
  const filterFields = columnsToFilterFields(columns)

  $: exportUrl = buildExportUrl()

  onMount(() => {
    const next = paramsFromLocation({ q: query, filters, location_id: locationId, sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage })
    query = next.q
    filters = next.filters || []
    locationId = next.location_id || ""
    sortKey = next.sort || "observed_at"
    sortDirection = next.direction || "desc"
    currentPage = next.page
    perPage = next.per_page

    window.addEventListener("popstate", handlePopState)
    window.addEventListener("live-audit", handleLiveAudit)
    pollTimer = window.setInterval(fetchRecent, 10000)
    fetchRecent()

    return () => {
      window.removeEventListener("popstate", handlePopState)
      window.removeEventListener("live-audit", handleLiveAudit)
      window.clearInterval(pollTimer)
    }
  })

  onDestroy(() => {
    window.clearInterval(pollTimer)
  })

  function state() {
    return {
      q: query,
      filters: serializeFilters(filters) || undefined,
      location_id: locationId || undefined,
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

  function handleSearch(params) {
    query = params.q || ""
    currentPage = 1
    fetchPage(true)
  }

  function handleFiltersChange(nextFilters) {
    filters = nextFilters
    currentPage = 1
    fetchPage(true)
  }

  function handleClearAll() {
    query = ""
    filters = []
    currentPage = 1
    fetchPage(true)
  }

  function handlePopState() {
    const next = paramsFromLocation({ q: query, filters, location_id: locationId, sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage })
    query = next.q
    filters = next.filters || []
    locationId = next.location_id || ""
    sortKey = next.sort || "observed_at"
    sortDirection = next.direction || "desc"
    currentPage = next.page
    perPage = next.per_page
    fetchPage(false)
  }

  async function fetchPage(push) {
    if (!endpoints.index) return

    loading = true
    if (push) updateHistory(endpoints.index, state())

    const url = `${endpoints.index}.json?${toQueryString(state())}`
    const response = await fetch(url, { headers: { accept: "application/json" } }).catch(() => null)
    loading = false
    if (response?.status === 304) return
    if (!response?.ok) {
      loadError = await errorMessage(response)
      return
    }

    const payload = await response.json()
    loadError = ""
    rows = payload.rows || []
    filters = payload.filters || filters
    totalCount = payload.totalCount || 0
    currentPage = payload.currentPage || currentPage
    perPage = payload.perPage || perPage
    sortKey = payload.sortKey || sortKey
    sortDirection = payload.sortDirection || sortDirection
    lastObservedAt = latestObservedAt(rows)
  }

  function handleLiveAudit(event) {
    if (!liveEligible()) return
    prependRows([event.detail])
  }

  async function fetchRecent() {
    if (!liveEligible() || !endpoints.recent) return

    const url = new URL(endpoints.recent, window.location.origin)
    if (lastObservedAt) url.searchParams.set("after", lastObservedAt)
    url.searchParams.set("limit", "25")

    const response = await fetch(url, { headers: { accept: "application/json" } }).catch(() => null)
    if (response?.status === 304) return
    if (!response?.ok) {
      loadError = await errorMessage(response)
      return
    }

    const recentRows = await response.json().catch(() => [])
    if (!Array.isArray(recentRows)) return

    loadError = ""
    prependRows(recentRows)
  }

  async function errorMessage(response) {
    if (!response) return "Unable to load audit data."
    if (response.status !== 503) return "Unable to load audit data."

    const payload = await response.json().catch(() => null)
    return payload?.error || "Query timed out. Narrow the search and try again."
  }

  function prependRows(nextRows) {
    const seen = new Set(rows.map(rowIdentifier).filter(Boolean))
    const additions = nextRows
      .filter(Boolean)
      .filter((row) => {
        const key = rowIdentifier(row)
        if (!key || seen.has(key)) return false
        seen.add(key)
        return true
      })
      .map((row) => ({ ...row, __new: true }))

    if (additions.length === 0) return

    rows = [...additions, ...rows].slice(0, perPage)
    totalCount += additions.length
    lastObservedAt = latestObservedAt(rows)

    window.setTimeout(() => {
      rows = rows.map((row) => ({ ...row, __new: false }))
    }, 320)
  }

  function liveEligible() {
    return !query && !locationId && filters.length === 0 && currentPage === 1 && sortKey === "observed_at" && sortDirection === "desc"
  }

  function rowIdentifier(row) {
    return row?.dedupe_key || [row?.observed_at, row?.sensor_id, row?.source_mac, row?.ssid].join("|")
  }

  function latestObservedAt(nextRows) {
    return nextRows.map((row) => row.observed_at).filter(Boolean).sort().pop() || null
  }

  function buildExportUrl() {
    const base = endpoints.export || "/audit_logs/export"
    const params = { q: query, filters: serializeFilters(filters) || undefined, location_id: locationId || undefined, sort: sortKey, direction: sortDirection, per_page: perPage }
    const queryString = toQueryString(params)
    return queryString ? `${base}?${queryString}` : base
  }

  async function handleExport(event) {
    event.preventDefault()
    loadError = ""

    const response = await fetch(exportUrl, {
      headers: { accept: "application/json" },
      redirect: "manual"
    }).catch(() => null)

    if (!response) {
      loadError = "Unable to start CSV export."
      return
    }

    if (response.ok || response.status === 0 || (response.status >= 300 && response.status < 400)) {
      window.location.href = response.headers.get("Location") || exportUrl
      return
    }

    const payload = await response.json().catch(() => null)
    loadError = payload?.error || "Unable to start CSV export."
  }
</script>

<div>
  <div class="mb-3 flex items-center justify-between gap-3">
    <h1 class="text-2xl font-bold text-(--color-text)">Audit Logs</h1>
    <a class="rounded-md border border-(--color-border-strong) bg-(--color-surface) px-3 py-2 text-sm font-semibold text-(--color-accent-vivid) hover:bg-(--color-accent-surface)" href={exportUrl} on:click={handleExport}>Export CSV</a>
  </div>

  <GridToolbar
    query={query}
    {filters}
    fields={filterFields}
    onSearch={handleSearch}
    onFiltersChange={handleFiltersChange}
    onClearAll={handleClearAll}
    placeholder="Search sensor, MAC, SSID, username, fingerprint, WPS"
  />

  {#if loadError}
    <div class="mb-3 rounded-md border border-(--color-danger-border) bg-(--color-danger-surface) px-3 py-2 text-sm text-(--color-danger-text)" role="alert">{loadError}</div>
  {/if}

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
    rowKey={rowIdentifier}
  />
</div>
