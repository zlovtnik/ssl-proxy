<script>
  import QueryBuilder from "./QueryBuilder.svelte"

  let { onFilterChange = () => {} } = $props()

  const fields = [
    { key: "source_mac", label: "MAC", type: "select" },
    { key: "destination_bssid", label: "Dest BSSID", type: "select" },
    { key: "ssid", label: "SSID", type: "select" },
    { key: "location_id", label: "Location", type: "select" },
    { key: "registered_username", label: "Registered Username", type: "select" },
    { key: "signal_dbm", label: "Signal", type: "number" }
  ]

  async function fetchDistinctValues(fieldKey) {
    const response = await fetch(`/identities/distinct_values?field=${fieldKey}`)
    if (!response.ok) return []
    return await response.json()
  }

  function handleChange(filters, meta) {
    onFilterChange(filters, meta)
  }
</script>

<QueryBuilder {fields} onChange={handleChange} onFetchValues={fetchDistinctValues} />
