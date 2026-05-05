<script>
  import { onMount } from "svelte"
  import PanelSkeletonRows from "../components/PanelSkeletonRows.svelte"

  export let initial = {}

  let endpoint = initial.endpoint || "/health/sync_data.json"
  let syncDataRows = []
  let syncRelationRows = []
  let loading = true
  let error = ""
  let fetchedAt = ""

  onMount(fetchRows)

  async function fetchRows() {
    loading = true
    error = ""
    const response = await fetch(endpoint, { headers: { accept: "application/json" } }).catch(() => null)

    if (!response?.ok) {
      error = "Unable to load sync health."
      loading = false
      return
    }

    let payload
    try {
      payload = await response.json()
    } catch (err) {
      console.warn("Unable to parse sync health response.", err)
      error = "Unable to parse sync health response."
      loading = false
      return
    }

    syncDataRows = payload.syncDataRows || []
    syncRelationRows = payload.syncRelationRows || []
    fetchedAt = payload.fetchedAt || new Date().toISOString()
    loading = false
  }
</script>

<section class="data-table-wrap section-spaced">
  <h2>Usable Sync Data</h2>
  {#if error}<p class="status-alert">{error}</p>{/if}
  <table class="data-table">
    <thead>
      <tr>
        <th>Signal</th>
        <th>Source</th>
        <th>Value</th>
        <th>Detail</th>
        <th>Last Seen</th>
      </tr>
    </thead>
    <tbody>
      {#if loading}
        <PanelSkeletonRows rows={5} columns={5} />
      {:else if syncDataRows.length}
        {#each syncDataRows as row}
          <tr>
            <td>{row.label}</td>
            <td>{row.source}</td>
            <td>{row.value}</td>
            <td>{row.detail}</td>
            <td>{row.lastSeen || "n/a"}</td>
          </tr>
        {/each}
      {:else}
        <tr><td colspan="5" class="empty-state">No sync health data found.</td></tr>
      {/if}
    </tbody>
  </table>
  {#if fetchedAt}<p class="muted">Last fetched {new Date(fetchedAt).toLocaleString()}</p>{/if}
</section>

<section class="data-table-wrap section-spaced">
  <h2>Important Relations</h2>
  <table class="data-table">
    <thead>
      <tr>
        <th>Relation</th>
        <th>Kind</th>
        <th>Role</th>
        <th>Estimated Rows</th>
        <th>Size</th>
      </tr>
    </thead>
    <tbody>
      {#if loading}
        <PanelSkeletonRows rows={5} columns={5} />
      {:else if syncRelationRows.length}
        {#each syncRelationRows as row}
          <tr>
            <td>{row.name}</td>
            <td>{row.kind}</td>
            <td>{row.role}</td>
            <td>{row.estimatedRows}</td>
            <td>{row.totalSize}</td>
          </tr>
        {/each}
      {:else}
        <tr><td colspan="5" class="empty-state">No relation map found.</td></tr>
      {/if}
    </tbody>
  </table>
</section>
