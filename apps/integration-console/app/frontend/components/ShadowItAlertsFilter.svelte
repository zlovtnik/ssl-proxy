<script>
  import QueryBuilder from "./QueryBuilder.svelte"

  let { onFilterChange = () => {}, initialFilters = [] } = $props()

  const fields = [
    { key: "source_mac", label: "Source MAC", type: "select" },
    { key: "destination_bssid", label: "Dest BSSID", type: "select" },
    { key: "ssid", label: "SSID", type: "select" },
    { key: "sensor_id", label: "Sensor", type: "select" },
    { key: "location_id", label: "Location", type: "select" },
    { key: "reason", label: "Reason", type: "select" },
    { key: "signal_dbm", label: "Signal", type: "number" }
  ]

  async function fetchDistinctValues(fieldKey) {
    const response = await fetch(`/shadow_it_alerts/distinct_values?field=${fieldKey}`)
    if (!response.ok) return []
    return await response.json()
  }

  function handleChange(filters, meta) {
    onFilterChange(filters, meta)
  }
</script>

<QueryBuilder {fields} filters={initialFilters} onChange={handleChange} onFetchValues={fetchDistinctValues} />
