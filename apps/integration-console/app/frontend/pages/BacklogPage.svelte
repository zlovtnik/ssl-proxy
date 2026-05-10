<script>
  import BacklogActions from "../components/BacklogActions.svelte"
  import DataGrid from "../components/DataGrid.svelte"
  import GridToolbar from "../components/GridToolbar.svelte"
  import Select from "../components/Select.svelte"
  import { requestJson, errorMessages } from "../lib/api"
  import { formatTime } from "../lib/format"
  import { columnsToFilterFields } from "../lib/grid"
  import { paramsFromLocation, serializeFilters, toQueryString, updateHistory } from "../lib/url"

  export let initial = {}

  let rows = initial.rows || []
  let status = initial.status || ""
  let filters = initial.filters || []
  let totalCount = initial.totalCount || rows.length
  let totalPages = initial.totalPages || 1
  let currentPage = initial.currentPage || 1
  let perPage = initial.perPage || 50
  let sortKey = initial.sortKey || "updated_at"
  let sortDirection = initial.sortDirection || "asc"
  let loading = false
  let retrying = ""
  let loadError = ""
  let notice = ""

  const endpoints = initial.endpoints || {}
  const statusOptions = [
    { label: "All", value: "" },
    { label: "Pending", value: "pending" },
    { label: "Failed", value: "sync_failed" }
  ]

  $: columns = [
    { key: "dedupe_key", label: "Dedupe Key", shortLabel: "Dedupe", sortable: true, size: "xl" },
    { key: "stream_name", label: "Subject", sortable: true, size: "md" },
    { key: "status", label: "Status", sortable: true, size: "sm" },
    { key: "attempt_count", label: "Attempts", sortable: true, size: "sm", filterType: "number" },
    { key: "updated_at", label: "Updated", sortable: true, size: "md", format: formatTime, filterType: "date" },
    {
      key: "__actions",
      label: "Action",
      size: "action",
      component: BacklogActions,
      componentProps: (_value, row) => ({ row, onRetry: retryRow, disabled: retrying === row.id })
    }
  ]
  $: filterFields = columnsToFilterFields(columns)

  function state() {
    return {
      status: status || undefined,
      filters: serializeFilters(filters) || undefined,
      sort: sortKey,
      direction: sortDirection,
      page: currentPage,
      per_page: perPage
    }
  }

  function handleStatusChange() {
    currentPage = 1
    fetchPage(true)
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

  function handleFiltersChange(nextFilters) {
    filters = nextFilters
    currentPage = 1
    fetchPage(true)
  }

  async function fetchPage(push) {
    if (!endpoints.index) return

    loading = true
    loadError = ""
    if (push) updateHistory(endpoints.index, state())

    try {
      const payload = await requestJson(`${endpoints.index}.json?${toQueryString(state())}`)
      rows = payload.rows || []
      filters = payload.filters || filters
      status = payload.status || ""
      totalCount = payload.totalCount || rows.length
      totalPages = payload.totalPages || 1
      currentPage = payload.currentPage || currentPage
      perPage = payload.perPage || perPage
      sortKey = payload.sortKey || sortKey
      sortDirection = payload.sortDirection || sortDirection
    } catch (error) {
      loadError = errorMessages(error).join(", ")
    } finally {
      loading = false
    }
  }

  async function retryRow(row) {
    retrying = row.id
    loadError = ""
    notice = ""

    try {
      const payload = await requestJson(row.retry_url, { method: "POST" })
      notice = payload?.notice || "Retry published."
      await fetchPage(false)
    } catch (error) {
      loadError = errorMessages(error).join(", ")
    } finally {
      retrying = ""
    }
  }

  function rowKey(row) {
    return row.id
  }

  const next = paramsFromLocation({ filters, sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage })
  filters = next.filters || []
  sortKey = next.sort || sortKey
  sortDirection = next.direction || sortDirection
  currentPage = next.page ?? currentPage
  perPage = next.per_page ?? perPage
</script>

<div>
  <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
    <h1 class="text-2xl font-bold text-(--color-text)">Backlog Manager</h1>
  </div>

  {#if notice}
    <div class="mb-3 rounded-md border border-(--color-border-strong) bg-(--color-accent-surface) px-3 py-2 text-sm text-(--color-accent-vivid)" role="status">{notice}</div>
  {/if}

  {#if loadError}
    <div class="mb-3 rounded-md border border-(--color-danger-border) bg-(--color-danger-surface) px-3 py-2 text-sm text-(--color-danger-text)" role="alert">{loadError}</div>
  {/if}

  <GridToolbar
    query=""
    {filters}
    fields={filterFields}
    searchable={false}
    onSearch={() => {}}
    onFiltersChange={handleFiltersChange}
  >
    <Select slot="controls" label="Status" bind:value={status} options={statusOptions} onChange={handleStatusChange} />
  </GridToolbar>

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
    rowKey={rowKey}
  />
</div>
