<script>
  import DataGrid from "../components/DataGrid.svelte"
  import FilterBar from "../components/FilterBar.svelte"
  import ResourceActions from "../components/ResourceActions.svelte"
  import ResourceForm from "../components/ResourceForm.svelte"
  import { requestJson, errorMessages } from "../lib/api"
  import { paramsFromLocation, toQueryString, updateHistory } from "../lib/url"

  export let initial = {}
  export let config = {}

  let rows = initial.rows || []
  let mode = initial.mode || "index"
  let formRecord = initial.current ? { ...initial.current } : null
  let formErrors = initial.errors || []
  let query = initial.query || ""
  let totalCount = initial.totalCount || rows.length
  let totalPages = initial.totalPages || 1
  let currentPage = initial.currentPage || 1
  let perPage = initial.perPage || 50
  let sortKey = initial.sortKey || config.defaultSort || ""
  let sortDirection = initial.sortDirection || config.defaultDirection || "asc"
  let loading = false
  let submitting = false
  let loadError = ""
  let notice = ""

  const endpoints = initial.endpoints || {}

  $: columns = [
    ...(config.columns || []),
    {
      key: "__actions",
      label: "Actions",
      width: "w-40",
      component: ResourceActions,
      componentProps: (_value, row) => ({
        row,
        deleteLabel: config.deleteLabel || "Remove",
        onEdit: startEdit,
        onDelete: deleteRow
      })
    }
  ]

  function state() {
    return {
      q: config.search ? query : undefined,
      sort: sortKey,
      direction: sortDirection,
      page: currentPage,
      per_page: perPage
    }
  }

  function startNew() {
    formErrors = []
    formRecord = { ...(config.emptyRecord || {}) }
    mode = "inline-form"
  }

  function startEdit(row) {
    formErrors = []
    formRecord = { ...row }
    mode = "inline-form"
  }

  function cancelForm() {
    if (initial.mode === "form") {
      window.location.href = endpoints.index || "/"
      return
    }

    formErrors = []
    formRecord = null
    mode = "index"
  }

  async function saveRecord(record) {
    submitting = true
    formErrors = []
    notice = ""

    const updateUrl = record.update_url
    const url = updateUrl || endpoints.create
    const method = updateUrl ? "PATCH" : "POST"

    try {
      const payload = await requestJson(url, {
        method,
        body: { [config.paramKey]: record }
      })

      if (initial.mode === "form") {
        window.location.href = payload?.redirectUrl || endpoints.index || "/"
        return
      }

      notice = config.savedMessage || "Saved."
      mode = "index"
      formRecord = null
      await fetchPage(false)
    } catch (error) {
      formErrors = errorMessages(error)
    } finally {
      submitting = false
    }
  }

  async function deleteRow(row) {
    const label = row.match_label || row.display_name || row.location_id || row.mac_hint || row.id
    if (!window.confirm(`${config.deleteConfirm || "Remove"} ${label}?`)) return

    loading = true
    loadError = ""
    notice = ""
    try {
      await requestJson(row.delete_url, { method: "DELETE" })
      notice = config.deletedMessage || "Removed."
      await fetchPage(false)
    } catch (error) {
      loadError = errorMessages(error).join(", ")
    } finally {
      loading = false
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

  async function fetchPage(push) {
    if (!endpoints.index) return

    loading = true
    loadError = ""
    if (push) updateHistory(endpoints.index, state())

    try {
      const payload = await requestJson(`${endpoints.index}.json?${toQueryString(state())}`)
      rows = payload.rows || []
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

  function rowKey(row) {
    return row.id || row.device_id || row.location_id || row.ssid
  }

  function initializeFromUrl() {
    const next = paramsFromLocation({ q: query, sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage })
    query = next.q
    sortKey = next.sort || sortKey
    sortDirection = next.direction || sortDirection
    currentPage = next.page ?? currentPage
    perPage = next.per_page ?? perPage
  }

  initializeFromUrl()
</script>

<div>
  <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
    <h1 class="text-2xl font-bold text-(--color-text)">{config.title}</h1>
    {#if initial.mode !== "form"}
      <button
        type="button"
        class="min-h-9 rounded-md border border-(--color-border-strong) bg-(--color-surface) px-3 py-2 text-sm font-semibold text-(--color-accent-vivid) hover:bg-(--color-accent-surface)"
        on:click={startNew}
      >
        {config.newLabel || "New"}
      </button>
    {/if}
  </div>

  {#if notice}
    <div class="mb-3 rounded-md border border-(--color-border-strong) bg-(--color-accent-surface) px-3 py-2 text-sm text-(--color-accent-vivid)" role="status">{notice}</div>
  {/if}

  {#if loadError}
    <div class="mb-3 rounded-md border border-(--color-danger-border) bg-(--color-danger-surface) px-3 py-2 text-sm text-(--color-danger-text)" role="alert">{loadError}</div>
  {/if}

  {#if mode !== "index" && formRecord}
    <ResourceForm
      title={formRecord.update_url ? config.editTitle : config.newTitle}
      fields={config.fields || []}
      record={formRecord}
      errors={formErrors}
      {submitting}
      submitLabel={config.submitLabel || "Save"}
      cancelLabel={initial.mode === "form" ? "Back" : "Cancel"}
      onSubmit={saveRecord}
      onCancel={cancelForm}
    />
  {/if}

  {#if initial.mode !== "form"}
    {#if config.search}
      <FilterBar query={query} onSearch={handleSearch} placeholder={config.searchPlaceholder || "Search"} />
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
  {/if}
</div>
