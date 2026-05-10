<script>
  import { onMount } from "svelte"
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
  let sortKey = initial.sortKey || "last_seen"
  let sortDirection = initial.sortDirection || "desc"
  let query = initial.query || ""
  let filters = initial.filters || []
  let loading = false
  let loadError = ""

  const endpoints = initial.endpoints || {}
  const columns = [
    { key: "ssid", label: "SSID", size: "md", sortable: true },
    {
      key: "client_mac",
      label: "Client MAC",
      shortLabel: "Client",
      size: "md",
      sortable: true,
      component: MacChip,
      componentProps: (value) => ({
        mac: value,
        display: value,
        masked: false
      })
    },
    { key: "known_bssid", label: "Known BSSID", shortLabel: "BSSID", size: "md", sortable: true },
    { key: "probe_count", label: "Probes", size: "sm", sortable: true },
    { key: "first_seen", label: "First Seen", size: "md", sortable: true },
    { key: "last_seen", label: "Last Seen", size: "md", sortable: true }
  ]
  const filterFields = columnsToFilterFields(columns)

  $: exportUrl = buildExportUrl(query, filters, sortKey, sortDirection, currentPage, perPage)

  onMount(() => {
    const next = paramsFromLocation({ q: query, filters, sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage })
    query = next.q
    filters = next.filters || []
    sortKey = next.sort || "last_seen"
    sortDirection = next.direction || "desc"
    currentPage = next.page
    perPage = next.per_page

    window.addEventListener("popstate", handlePopState)
    fetchPage(false)

    return () => {
      window.removeEventListener("popstate", handlePopState)
    }
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
    sortKey = next.sort || "last_seen"
    sortDirection = next.direction || "desc"
    currentPage = next.page
    perPage = next.per_page
    fetchPage(false)
  }

  let activeFetchId = 0

  async function fetchPage(push) {
    const requestId = ++activeFetchId
    loading = true

    const url = `${endpoints.index}.json?${toQueryString(state())}`
    const response = await fetch(url, { headers: { accept: "application/json" } }).catch((err) => {
      if (requestId === activeFetchId) {
        loadError = `Network error: ${err?.message || "request failed"}`
        loading = false
      }
      return null
    })

    if (requestId !== activeFetchId) return
    if (response?.status === 304) {
      loading = false
      return
    }
    if (!response?.ok) {
      loadError = await errorMessage(response)
      loading = false
      return
    }

    const payload = await response.json()
    if (requestId !== activeFetchId) return

    rows = payload.rows || []
    filters = payload.filters || filters
    totalCount = payload.totalCount || 0
    currentPage = payload.currentPage || currentPage
    perPage = payload.perPage || perPage
    sortKey = payload.sortKey || sortKey
    sortDirection = payload.sortDirection || sortDirection
    loadError = ""

    if (push) updateHistory(endpoints.index, state())
    loading = false
  }

  function buildExportUrl(q, filters, sort, direction, page, per_page) {
    if (!endpoints.export) return null
    return `${endpoints.export}?${toQueryString({
      q,
      filters: serializeFilters(filters) || undefined,
      sort,
      direction,
      page,
      per_page,
    })}`
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
    <h2>Network Clients</h2>
    <ThemeSwitcher />
  </div>
  <GridToolbar
    query={query}
    fields={filterFields}
    searchable={true}
    placeholder="Search SSID, MAC, or BSSID"
    onSearch={handleSearch}
    onFiltersChange={handleFiltersChange}
    onClearAll={handleClearAll}
    {exportUrl}
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
    rowKey={(row) => `${row.ssid}-${row.client_mac}`}
  />
  {#if loadError}
    <div class="notification is-danger">
      <p><strong>Error loading network clients:</strong> {loadError}</p>
    </div>
  {/if}
</section>
