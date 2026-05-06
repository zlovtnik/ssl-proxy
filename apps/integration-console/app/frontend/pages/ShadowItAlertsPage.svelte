<script>
  import GridToolbar from "../components/GridToolbar.svelte"
  import { paramsFromLocation } from "../lib/url"

  export let initial = {}

  const fields = [
    { key: "source_mac", label: "Source MAC", shortLabel: "Source", type: "select" },
    { key: "destination_bssid", label: "Destination BSSID", shortLabel: "Dest BSSID", type: "select" },
    { key: "ssid", label: "SSID", type: "select" },
    { key: "sensor_id", label: "Sensor", type: "select" },
    { key: "location_id", label: "Location", type: "select" },
    { key: "reason", label: "Reason", type: "select" },
    { key: "signal_dbm", label: "Signal", type: "number" }
  ]

  let query = initial.query || ""
  let filters = initial.filters || []

  const next = paramsFromLocation({ q: query, filters })
  query = next.q
  filters = next.filters || []

  async function fetchDistinctValues(fieldKey) {
    const response = await fetch(`/shadow_it_alerts/distinct_values?field=${fieldKey}`)
    if (!response.ok) return []
    return await response.json()
  }

  function handleSearch(params) {
    query = params.q || ""
    navigate()
  }

  function handleFilterChange(nextFilters, meta) {
    filters = nextFilters || []
    navigate(meta?.serialized)
  }

  function navigate(serializedFilters = null) {
    const url = new URL(window.location)
    if (query) {
      url.searchParams.set('q', query)
    } else {
      url.searchParams.delete('q')
    }
    const serialized = serializedFilters ?? (filters.length ? JSON.stringify(filters) : "")
    if (serialized) {
      url.searchParams.set('filters', serialized)
    } else {
      url.searchParams.delete('filters')
    }
    url.searchParams.delete('page')
    window.location.href = url.toString()
  }
</script>

<div class="mb-4">
  <GridToolbar
    {query}
    {filters}
    {fields}
    onSearch={handleSearch}
    onFiltersChange={handleFilterChange}
    onFetchValues={fetchDistinctValues}
    placeholder="Search MAC, SSID, sensor, location, reason"
  />
</div>
