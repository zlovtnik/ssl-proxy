<script>
  import { tick } from "svelte"
  import DataGrid from "../components/DataGrid.svelte"
  import MetricCard from "../components/MetricCard.svelte"
  import RangePicker from "../components/RangePicker.svelte"
  import IntegrationActions from "../components/IntegrationActions.svelte"
  import { requestJson, errorMessages } from "../lib/api"
  import { toQueryString, updateHistory } from "../lib/url"

  const { initial = {} } = $props()
  const initialValue = (key, fallback) => initial[key] ?? fallback

  let rows = $state(initialValue("rows", []))
  let summary = $state(initialValue("summary", {}))
  let sortKey = $state(initialValue("sortKey", "name"))
  let sortDirection = $state(initialValue("sortDirection", "asc"))
  let currentPage = $state(initialValue("currentPage", 1))
  let perPage = $state(initialValue("perPage", 50))
  let totalCount = $state(initialValue("totalCount", initialValue("rows", []).length))
  let loading = $state(false)
  let notice = $state("")
  let noticeTimer = null
  let error = $state("")
  let triggerRow = $state(null)
  let triggerRange = $state({ range_type: "cursor", from_value: "", to_value: "" })
  let triggerError = $state("")
  let triggerModal = $state(null)
  let triggerCloseButton = $state(null)
  let triggerOpener = $state(null)

  const endpoints = initialValue("endpoints", {})

  const cards = $derived([
    { label: "Enabled Integrations", value: summary.total_enabled || 0, status: "neutral", icon: "backlog" },
    { label: "Runs 24h", value: summary.runs_24h || 0, status: "neutral", icon: "audit" },
    { label: "Failed 24h", value: summary.failed_24h || 0, status: summary.failed_24h > 0 ? "alert" : "ok", icon: "alert" },
    { label: "Avg Duration", value: `${summary.avg_duration_24h || 0}s`, status: "neutral", icon: "health" }
  ])

  const columns = [
    { key: "name", label: "Name", sortable: true, href: (row) => row.show_url, size: "lg" },
    { key: "flow", label: "Source -> Destination", format: (_value, row) => `${row.source_type} -> ${row.destination_type}`, size: "lg" },
    { key: "schedule_cron", label: "Schedule", format: (value) => value || "Manual", size: "md" },
    { key: "last_run", label: "Last run", sortable: false, format: (value) => value ? `${value.status} ${formatDate(value.created_at)}` : "None", size: "lg" },
    { key: "last_rows", label: "Rows", format: (_value, row) => row.last_run ? `${row.last_run.rows_written || 0} / ${row.last_run.rows_read || 0}` : "-", size: "sm" },
    { key: "enabled", label: "Status", sortable: true, format: (value) => value ? "Enabled" : "Disabled", size: "sm" },
    { key: "__actions", label: "Actions", component: IntegrationActions, componentProps: (_value, row) => ({ row, onTrigger: openTrigger, onDisable: disableIntegration }), size: "action" }
  ]

  function formatDate(value) {
    return value ? new Date(value).toLocaleString() : ""
  }

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

  function showNotice(message) {
    if (noticeTimer) clearTimeout(noticeTimer)
    notice = message
    noticeTimer = setTimeout(() => {
      notice = ""
      noticeTimer = null
    }, 4000)
  }

  async function fetchPage(push) {
    loading = true
    notice = ""
    error = ""
    const query = { sort: sortKey, direction: sortDirection, page: currentPage, per_page: perPage }
    if (push) updateHistory(endpoints.index, query)
    try {
      const payload = await requestJson(`${endpoints.index}.json?${toQueryString(query)}`)
      rows = payload.rows || []
      summary = payload.summary || summary
      totalCount = payload.totalCount || rows.length
      currentPage = payload.currentPage || currentPage
      perPage = payload.perPage || perPage
    } catch (requestError) {
      error = errorMessages(requestError).join(", ")
    } finally {
      loading = false
    }
  }

  async function openTrigger(row) {
    notice = ""
    triggerOpener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    triggerRow = row
    triggerRange = { range_type: "cursor", from_value: "", to_value: "" }
    triggerError = ""
    await tick()
    triggerCloseButton?.focus()
  }

  function closeTrigger() {
    triggerRow = null
    triggerError = ""
    triggerOpener?.focus()
    triggerOpener = null
  }

  function triggerFocusableElements() {
    if (!triggerModal) return []
    return Array.from(
      triggerModal.querySelectorAll("a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])")
    ).filter((element) => element instanceof HTMLElement && element.offsetParent !== null)
  }

  function handleTriggerKeydown(event) {
    if (event.key === "Escape") {
      event.preventDefault()
      closeTrigger()
      return
    }
    if (event.key !== "Tab") return

    const focusable = triggerFocusableElements()
    if (focusable.length === 0) {
      event.preventDefault()
      triggerModal?.focus()
      return
    }

    const first = focusable[0]
    const last = focusable[focusable.length - 1]
    if (event.shiftKey && document.activeElement === first) {
      event.preventDefault()
      last.focus()
    } else if (!event.shiftKey && document.activeElement === last) {
      event.preventDefault()
      first.focus()
    }
  }

  async function submitTrigger() {
    if (triggerError || !triggerRow) return
    try {
      const payload = await requestJson(triggerRow.trigger_url, {
        method: "POST",
        body: { integration_run: triggerRange }
      })
      if (typeof payload.redirectUrl === "string" && payload.redirectUrl.length > 0) {
        window.location.href = payload.redirectUrl
      } else {
        triggerError = "Missing redirect URL in response"
      }
    } catch (requestError) {
      triggerError = errorMessages(requestError).join(", ")
    }
  }

  async function disableIntegration(row) {
    if (!window.confirm(`Disable ${row.name}?`)) return
    try {
      await requestJson(row.delete_url, { method: "DELETE" })
      error = ""
      await fetchPage(false)
      showNotice("Integration disabled.")
    } catch (requestError) {
      error = errorMessages(requestError).join(", ")
    }
  }
</script>

<div class="grid gap-4">
  <div class="flex flex-wrap items-center justify-between gap-3">
    <h1 class="text-2xl font-bold text-(--color-text)">Integrations</h1>
    <a class="min-h-9 rounded-md border border-(--color-border-strong) bg-(--color-surface) px-3 py-2 text-sm font-semibold text-(--color-accent-vivid)" href="/integrations/new">New integration</a>
  </div>

  {#if notice}<div class="rounded-md border border-(--color-border-strong) bg-(--color-accent-surface) px-3 py-2 text-sm">{notice}</div>{/if}
  {#if error}<div class="rounded-md border border-(--color-danger-border) bg-(--color-danger-surface) px-3 py-2 text-sm text-(--color-danger-text)">{error}</div>{/if}

  <div class="grid gap-3 md:grid-cols-4">
    {#each cards as card}
      <MetricCard {...card} />
    {/each}
  </div>

  <DataGrid {columns} {rows} {totalCount} {currentPage} {perPage} {sortKey} {sortDirection} {loading} onSort={sort} onPageChange={pageChange} />

  {#if triggerRow}
    <div class="fixed inset-0 z-40 grid place-items-center bg-(--color-surface-scrim) p-4">
      <div
        bind:this={triggerModal}
        class="w-full max-w-xl rounded-lg border border-(--color-border-strong) bg-(--color-surface) p-4 shadow-lg"
        role="dialog"
        aria-modal="true"
        aria-labelledby="trigger-dialog-title"
        tabindex="-1"
        onkeydown={handleTriggerKeydown}
      >
        <div class="mb-3 flex items-center justify-between gap-3">
          <h2 id="trigger-dialog-title" class="text-lg font-semibold">Trigger {triggerRow.name}</h2>
          <button bind:this={triggerCloseButton} type="button" class="rounded-md border px-2 py-1 text-sm" onclick={closeTrigger}>Close</button>
        </div>
        <RangePicker value={triggerRange} onChange={(value, nextError) => { triggerRange = value; triggerError = nextError }} />
        {#if triggerError}<div class="mt-3 text-sm text-(--color-danger-text)">{triggerError}</div>{/if}
        <div class="mt-4 flex justify-end">
          <button type="button" class="min-h-9 rounded-md border border-(--color-border-strong) px-3 py-2 text-sm font-semibold text-(--color-accent-vivid)" disabled={Boolean(triggerError)} onclick={submitTrigger}>Trigger run</button>
        </div>
      </div>
    </div>
  {/if}
</div>
