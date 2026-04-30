<script>
  import { onMount } from "svelte"
  import DataGrid from "../components/DataGrid.svelte"
  import { toQueryString } from "../lib/url"

  export let initial = {}

  const columns = [
    { key: "sensorId", label: "Sensor", sortable: true },
    { key: "locationId", label: "Location", sortable: true },
    { key: "lastSeenAt", label: "Last Seen", sortable: true },
    { key: "lastSignalDbm", label: "Signal", sortable: true },
    { key: "status", label: "Status", sortable: true }
  ]

  let endpoint = initial.endpoint || "/health/sensors.json"
  let rows = []
  let totalCount = 0
  let currentPage = 1
  let perPage = 25
  let sortKey = "last_seen_at"
  let sortDirection = "desc"
  let loading = true

  onMount(fetchPage)

  function handleSort(key) {
    const sortMap = {
      sensorId: "sensor_id",
      locationId: "location_id",
      lastSeenAt: "last_seen_at",
      lastSignalDbm: "last_signal_dbm",
      status: "status"
    }
    const nextSort = sortMap[key] || key
    sortDirection = sortKey === nextSort && sortDirection === "asc" ? "desc" : "asc"
    sortKey = nextSort
    currentPage = 1
    fetchPage()
  }

  function handlePageChange(page) {
    currentPage = page
    fetchPage()
  }

  async function fetchPage() {
    loading = true
    const query = toQueryString({ page: currentPage, per_page: perPage, sort: sortKey, direction: sortDirection })
    const response = await fetch(`${endpoint}?${query}`, { headers: { accept: "application/json" } }).catch(() => null)
    loading = false
    if (!response?.ok) return

    const payload = await response.json().catch(() => ({}))
    rows = payload.rows || []
    totalCount = payload.totalCount || 0
    currentPage = payload.currentPage || currentPage
    perPage = payload.perPage || perPage
    sortKey = payload.sortKey || sortKey
    sortDirection = payload.sortDirection || sortDirection
  }
</script>

<section class="table-wrap section-spaced">
  <h2>Sensors</h2>
  <DataGrid
    {columns}
    {rows}
    {totalCount}
    {currentPage}
    {perPage}
    sortKey={sortKey.replaceAll("_", "")}
    {sortDirection}
    {loading}
    onSort={handleSort}
    onPageChange={handlePageChange}
    rowKey={(row) => row.sensorId}
  />
</section>
