<script>
  import DataGrid from "../components/DataGrid.svelte"
  import { requestJson, errorMessages } from "../lib/api"
  import { toQueryString, updateHistory } from "../lib/url"

  export let initial = {}

  let rows = initial.rows || []
  let sortKey = initial.sortKey || "created_at"
  let sortDirection = initial.sortDirection || "desc"
  let currentPage = initial.currentPage || 1
  let perPage = initial.perPage || 50
  let totalCount = initial.totalCount || rows.length
  let loading = false
  let error = ""

  const endpoints = initial.endpoints || {}
  const columns = [
    { key: "integration_name", label: "Integration", size: "lg" },
    { key: "status", label: "Status", sortable: true, size: "sm" },
    { key: "triggered_by", label: "Triggered", sortable: true, size: "sm" },
    { key: "range", label: "Range", format: (_value, row) => `${row.from_value || "current"} -> ${row.to_value || "now"}`, size: "lg" },
    { key: "rows", label: "Rows R/W/E", format: (_value, row) => `${row.rows_read || 0}/${row.rows_written || 0}/${row.rows_errored || 0}`, size: "md" },
    { key: "created_at", label: "Created", sortable: true, format: (value) => value ? new Date(value).toLocaleString() : "", size: "lg" },
    { key: "show_url", label: "Open", href: (row) => row.show_url, format: () => "Open", size: "sm" }
  ]

  function sort(key) {
    sortDirection = sortKey === key && sortDirection === "asc" ? "desc" : "asc"
    sortKey = key
    currentPage = 1
    fetchPage(true)
  }

  function pageChange(page) {
    currentPage = page
    fetchPage(true)
  }

  async function fetchPage(push) {
    if (!endpoints.index) {
      error = "Configuration error: missing endpoint"
      loading = false
      return
    }
    loading = true
    error = ""
    const query = { sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage }
    if (push) updateHistory(endpoints.index, query)
    try {
      const payload = await requestJson(`${endpoints.index}.json?${toQueryString(query)}`)
      rows = payload.rows || []
      totalCount = payload.totalCount || rows.length
      currentPage = payload.currentPage || currentPage
      perPage = payload.perPage || perPage
    } catch (requestError) {
      error = errorMessages(requestError).join(", ")
    } finally {
      loading = false
    }
  }
</script>

<div class="grid gap-4">
  <div class="flex flex-wrap items-center justify-between gap-3">
    <h1 class="text-2xl font-bold text-(--color-text)">Integration Runs</h1>
    <a class="text-sm font-semibold text-(--color-accent-vivid) hover:underline" href="/integrations">Integrations</a>
  </div>
  {#if error}<div class="rounded-md border border-(--color-danger-border) bg-(--color-danger-surface) px-3 py-2 text-sm text-(--color-danger-text)">{error}</div>{/if}
  <DataGrid {columns} {rows} {totalCount} {currentPage} {perPage} {sortKey} {sortDirection} {loading} onSort={sort} onPageChange={pageChange} />
</div>
