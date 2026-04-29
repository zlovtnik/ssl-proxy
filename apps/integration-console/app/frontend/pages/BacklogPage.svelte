<script>
  import BacklogActions from "../components/BacklogActions.svelte"
  import DataGrid from "../components/DataGrid.svelte"
  import Select from "../components/Select.svelte"
  import { requestJson, errorMessages } from "../lib/api"
  import { formatTime } from "../lib/format"
  import { paramsFromLocation, toQueryString, updateHistory } from "../lib/url"

  export let initial = {}

  let rows = initial.rows || []
  let status = initial.status || ""
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
    { key: "dedupe_key", label: "Dedupe Key", sortable: true, width: "w-56" },
    { key: "stream_name", label: "Subject", sortable: true, width: "w-36" },
    { key: "status", label: "Status", sortable: true, width: "w-28" },
    { key: "attempt_count", label: "Attempts", sortable: true, width: "w-24" },
    { key: "updated_at", label: "Updated", sortable: true, width: "w-36", format: formatTime },
    {
      key: "__actions",
      label: "Action",
      width: "w-24",
      component: BacklogActions,
      componentProps: (_value, row) => ({ row, onRetry: retryRow, disabled: retrying === row.id })
    }
  ]

  function state() {
    return {
      status: status || undefined,
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

  async function fetchPage(push) {
    if (!endpoints.index) return

    loading = true
    loadError = ""
    if (push) updateHistory(endpoints.index, state())

    try {
      const payload = await requestJson(`${endpoints.index}.json?${toQueryString(state())}`)
      rows = payload.rows || []
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

  const next = paramsFromLocation({ sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage })
  sortKey = next.sort || sortKey
  sortDirection = next.direction || sortDirection
  currentPage = next.page
  perPage = next.per_page
</script>

<div>
  <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
    <h1 class="text-2xl font-bold text-[#c8e6c8]">Backlog Manager</h1>
    <Select label="Status" bind:value={status} options={statusOptions} onChange={handleStatusChange} />
  </div>

  {#if notice}
    <div class="mb-3 rounded-md border border-[#1f6b1f] bg-[#0f2d0f] px-3 py-2 text-sm text-[#bbf7d0]" role="status">{notice}</div>
  {/if}

  {#if loadError}
    <div class="mb-3 rounded-md border border-[#7f1d1d] bg-[#190d0d] px-3 py-2 text-sm text-[#fecaca]" role="alert">{loadError}</div>
  {/if}

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
