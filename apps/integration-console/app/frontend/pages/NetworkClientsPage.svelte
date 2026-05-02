<script>
  import { onMount } from "svelte"
  import DataGrid from "../components/DataGrid.svelte"
  import MacChip from "../components/MacChip.svelte"

  export let initial = {}

  const columns = [
    { key: "ssid", label: "SSID", sortable: false, minWidth: "min-w-32" },
    { 
      key: "client_mac", 
      label: "Client MAC", 
      sortable: false, 
      minWidth: "min-w-32",
      component: MacChip,
      componentProps: (value) => ({
        mac: value,
        display: value,
        masked: false
      })
    },
    { key: "known_bssid", label: "Known BSSID", sortable: false, minWidth: "min-w-32" },
    { key: "probe_count", label: "Probes", sortable: false, minWidth: "min-w-20" },
    { key: "first_seen", label: "First Seen", sortable: false, minWidth: "min-w-32" },
    { key: "last_seen", label: "Last Seen", sortable: false, minWidth: "min-w-32" }
  ]

  let endpoint = initial.endpoint || "/network_clients.json"
  let rows = []
  let filteredRows = []
  let loading = true
  let ssidFilter = ""

  onMount(fetchData)

  async function fetchData() {
    loading = true
    const r = await fetch(endpoint, { headers: { accept: "application/json" } }).catch(() => null)
    loading = false
    if (!r?.ok) return

    const payload = await r.json().catch(() => ({}))
    rows = payload.rows || []
    applyFilter()
  }

  function applyFilter() {
    if (!ssidFilter.trim()) {
      filteredRows = rows
    } else {
      const term = ssidFilter.toLowerCase()
      filteredRows = rows.filter(row => row.ssid?.toLowerCase().includes(term))
    }
  }

  function handleFilterChange() {
    applyFilter()
  }
</script>

<section class="table-wrap section-spaced">
  <h2>Network Clients</h2>
  <div style="margin-bottom: 16px;">
    <label for="ssid-filter">Filter by SSID:</label>
    <input 
      id="ssid-filter" 
      type="text" 
      bind:value={ssidFilter} 
      on:input={handleFilterChange}
      placeholder="Enter SSID..."
      style="margin-left: 8px; padding: 4px 8px;"
    />
  </div>
  <DataGrid
    {columns}
    rows={filteredRows}
    totalCount={filteredRows.length}
    currentPage={1}
    perPage={filteredRows.length}
    sortKey=""
    sortDirection="desc"
    {loading}
    filters={[]}
    filterFields={[]}
    onSort={() => {}}
    onPageChange={() => {}}
    onFiltersChange={() => {}}
    rowKey={(row) => `${row.ssid}-${row.client_mac}`}
  />
</section>
