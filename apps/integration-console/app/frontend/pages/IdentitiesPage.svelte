<script>
  import { onDestroy, onMount } from "svelte"
  import DataGrid from "../components/DataGrid.svelte"
  import GridToolbar from "../components/GridToolbar.svelte"
  import ThemeSwitcher from "../components/ThemeSwitcher.svelte"
  import MacChip from "../components/MacChip.svelte"
  import { columnsToFilterFields } from "../lib/grid"
  import { paramsFromLocation, serializeFilters, toQueryString, updateHistory } from "../lib/url"

  export let initial = {}

  let rows = initial.rows || []
  let totalCount = initial.totalCount || 0
  let currentPage = initial.currentPage || 1
  let perPage = initial.perPage || 50
  let sortKey = initial.sortKey || "last_occurred_at"
  let sortDirection = initial.sortDirection || "desc"
  let query = initial.query || ""
  let filters = initial.filters || []
  let loading = false
  let loadError = ""

  const endpoints = initial.endpoints || {}
  const columns = [
    {
      key: "source_mac",
      label: "MAC",
      size: "md",
      sortable: true,
      component: MacChip,
      componentProps: (value) => ({
        mac: value,
        display: value,
        masked: false
      })
    },
    { key: "bssid", label: "BSSID", size: "md", sortable: true },
    { key: "destination_bssid", label: "Dest BSSID", shortLabel: "Dest", size: "md", sortable: true },
    { key: "ssid", label: "SSID", size: "md", sortable: true },
    { key: "signal_dbm", label: "Signal", size: "sm", sortable: true },
    { key: "location_id", label: "Location", size: "md", sortable: true },
    { key: "username", label: "Username", size: "md" },
    { key: "registered_username", label: "Registered", shortLabel: "Reg", size: "md", sortable: true },
    { key: "display_name", label: "Device", size: "md", sortable: true },
    { key: "wps_device_name", label: "WPS Name", shortLabel: "WPS", size: "md" },
    { key: "last_occurred_at", label: "Last Occurred", shortLabel: "Last", size: "md", sortable: true }
  ]
  const filterFields = columnsToFilterFields(columns)

  onMount(() => {
    const next = paramsFromLocation({ q: query, filters, sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage })
    query = next.q
    filters = next.filters || []
    sortKey = next.sort || "last_occurred_at"
    sortDirection = next.direction || "desc"
    currentPage = next.page
    perPage = next.per_page

    window.addEventListener("popstate", handlePopState)
    fetchPage(false)

    return () => {
      window.removeEventListener("popstate", handlePopState)
    }
  })

  onDestroy(() => {
    window.removeEventListener("popstate", handlePopState)
  })

  function state() {
    return {
      q: query,
      filters: serializeFilters(filters) || undefined,
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
    const next = paramsFromLocation({ q: query, filters, sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage })
    query = next.q
    filters = next.filters || []
    sortKey = next.sort || "last_occurred_at"
    sortDirection = next.direction || "desc"
    currentPage = next.page
    perPage = next.per_page
    fetchPage(false)
  }

  async function fetchPage(push) {
    loading = true
    if (push) updateHistory(endpoints.index, state())

    const url = `${endpoints.index}.json?${toQueryString(state())}`
    const response = await fetch(url, { headers: { accept: "application/json" } }).catch((err) => {
      loading = false
      loadError = `Network error: ${err?.message || "request failed"}`
      return null
    })
    if (response?.status === 304) return
    if (!response?.ok) {
      loadError = await errorMessage(response)
      loading = false
      return
    }

    const payload = await response.json()
    loading = false
    loadError = ""
    rows = payload.rows || []
    filters = payload.filters || filters
    totalCount = payload.totalCount || 0
    currentPage = payload.currentPage || currentPage
    perPage = payload.perPage || perPage
    sortKey = payload.sortKey || sortKey
    sortDirection = payload.sortDirection || sortDirection
  }

  async function errorMessage(response) {
    try {
      const json = await response.json()
      return json.error || `HTTP ${response.status}`
    } catch {
      return `HTTP ${response.status}`
    }
  }
</script>

<section class="section-spaced">
  <div class="flex items-center justify-between gap-3 mb-4">
    <h2>MAC Identity Inventory</h2>
    <ThemeSwitcher />
  </div>
  <GridToolbar
    {query}
    fields={filterFields}
    searchable={true}
    placeholder="Search MAC, SSID, user, device, service"
    onSearch={handleSearch}
    onFiltersChange={handleFiltersChange}
    onClearAll={handleClearAll}
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
    rowKey={(row) => `${row.source_mac}-${row.bssid}`}
  />
  {#if loadError}
    <div class="notification is-danger">
      <p><strong>Error loading identities:</strong> {loadError}</p>
    </div>
  {/if}
</section>