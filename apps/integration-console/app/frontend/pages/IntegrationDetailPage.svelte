<script>
  import { tick } from "svelte"
  import DataGrid from "../components/DataGrid.svelte"
  import ParamSchemaForm from "../components/ParamSchemaForm.svelte"
  import RangePicker from "../components/RangePicker.svelte"
  import LineagePanel from "../components/LineagePanel.svelte"
  import { requestJson, errorMessages } from "../lib/api"

  export let initial = {}

  let integration = initial.integration || { enabled: true, source_type: "nats", destination_type: "postgres", params: {} }
  let runs = initial.runs || []
  let schemas = initial.schemas || {}
  let activeTab = initial.mode === "new" ? "config" : "history"
  let errors = []
  let notice = ""
  let submitting = false
  let replayRun = null
  let replayRange = { range_type: "cursor", from_value: "", to_value: "" }
  let replayError = ""
  let replayModal = null
  let replayCloseButton = null
  let replayOpener = null

  const endpoints = initial.endpoints || {}

  $: schema = schemas[integration.source_type] || {}

  const runColumns = [
    { key: "status", label: "Status", size: "sm" },
    { key: "triggered_by", label: "Triggered", size: "sm" },
    { key: "range", label: "Range", format: (_value, row) => `${row.from_value || "current"} -> ${row.to_value || "now"}`, size: "lg" },
    { key: "rows", label: "Rows R/W/E", format: (_value, row) => `${row.rows_read || 0}/${row.rows_written || 0}/${row.rows_errored || 0}`, size: "md" },
    { key: "duration_seconds", label: "Duration", format: (value) => value == null ? "-" : `${value}s`, size: "sm" },
    { key: "created_at", label: "Created", format: (value) => value ? new Date(value).toLocaleString() : "", size: "lg" },
    { key: "show_url", label: "Open", href: (row) => row.show_url, format: () => "Open", size: "sm" }
  ]

  function update(field, value) {
    integration = { ...integration, [field]: value }
  }

  async function save() {
    submitting = true
    errors = []
    notice = ""
    try {
      const url = integration.update_url || endpoints.create
      const method = integration.update_url ? "PATCH" : "POST"
      const payload = await requestJson(url, { method, body: { integration_config: integration } })
      if (payload.redirectUrl) {
        window.location.href = payload.redirectUrl
      } else {
        notice = "Integration saved."
      }
    } catch (error) {
      errors = errorMessages(error)
    } finally {
      submitting = false
    }
  }

  async function openReplay(row) {
    replayOpener = document.activeElement instanceof HTMLElement ? document.activeElement : null
    replayRun = row
    replayRange = { range_type: row.range_type || "cursor", from_value: row.from_value || "", to_value: row.to_value || "" }
    replayError = ""
    await tick()
    replayCloseButton?.focus()
  }

  function closeReplay() {
    replayRun = null
    replayError = ""
    replayOpener?.focus()
    replayOpener = null
  }

  function replayFocusableElements() {
    if (!replayModal) return []
    return Array.from(
      replayModal.querySelectorAll("a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled]), [tabindex]:not([tabindex='-1'])")
    ).filter((element) => element instanceof HTMLElement && element.offsetParent !== null)
  }

  function handleReplayKeydown(event) {
    if (event.key === "Escape") {
      event.preventDefault()
      closeReplay()
      return
    }
    if (event.key !== "Tab") return

    const focusable = replayFocusableElements()
    if (focusable.length === 0) {
      event.preventDefault()
      replayModal?.focus()
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

  async function submitReplay() {
    if (replayError || !replayRun) return
    try {
      const payload = await requestJson(integration.replay_url, { method: "POST", body: { integration_run: replayRange } })
      if (typeof payload.redirectUrl === "string" && payload.redirectUrl.length > 0) {
        window.location.href = payload.redirectUrl
      } else {
        replayError = "Missing redirect URL in response"
      }
    } catch (error) {
      replayError = errorMessages(error).join(", ")
    }
  }
</script>

<div class="grid gap-4">
  <div class="flex flex-wrap items-center justify-between gap-3">
    <h1 class="text-2xl font-bold text-(--color-text)">{integration.name || "New Integration"}</h1>
    <a class="text-sm font-semibold text-(--color-accent-vivid) hover:underline" href="/integrations">All integrations</a>
  </div>

  <div class="flex flex-wrap gap-2 border-b border-(--color-border-muted)">
    {#each ["config", "history", "lineage"] as tab}
      <button type="button" class={activeTab === tab ? "border-b-2 border-(--color-accent-vivid) px-3 py-2 text-sm font-semibold text-(--color-accent-vivid)" : "px-3 py-2 text-sm font-semibold text-(--color-text-muted)"} on:click={() => activeTab = tab}>{tab}</button>
    {/each}
  </div>

  {#if activeTab === "config"}
    <form class="grid gap-4 rounded-lg border border-(--color-border-muted) bg-(--color-surface) p-4" on:submit|preventDefault={save}>
      {#if errors.length}<div class="rounded-md border border-(--color-danger-border) bg-(--color-danger-surface) px-3 py-2 text-sm text-(--color-danger-text)">{errors.join(", ")}</div>{/if}
      {#if notice}<div class="rounded-md border border-(--color-border-strong) bg-(--color-accent-surface) px-3 py-2 text-sm">{notice}</div>{/if}
      <div class="grid gap-3 md:grid-cols-2">
        <label class="grid gap-1"><span class="text-xs font-semibold uppercase">Name</span><input class="min-h-9 rounded-md border px-3 text-sm" value={integration.name || ""} on:input={(event) => update("name", event.currentTarget.value)} /></label>
        <label class="grid gap-1"><span class="text-xs font-semibold uppercase">Slug</span><input class="min-h-9 rounded-md border px-3 text-sm" value={integration.slug || ""} on:input={(event) => update("slug", event.currentTarget.value)} /></label>
        <label class="grid gap-1"><span class="text-xs font-semibold uppercase">Source</span><select class="min-h-9 rounded-md border px-3 text-sm" value={integration.source_type || "nats"} on:change={(event) => update("source_type", event.currentTarget.value)}>{#each Object.keys(schemas) as type}<option value={type}>{type}</option>{/each}</select></label>
        <label class="grid gap-1"><span class="text-xs font-semibold uppercase">Destination</span><select class="min-h-9 rounded-md border px-3 text-sm" value={integration.destination_type || "postgres"} on:change={(event) => update("destination_type", event.currentTarget.value)}>{#each Object.keys(schemas) as type}<option value={type}>{type}</option>{/each}</select></label>
        <label class="grid gap-1"><span class="text-xs font-semibold uppercase">Stream</span><input class="min-h-9 rounded-md border px-3 text-sm" value={integration.stream_name || ""} placeholder="wireless.audit" on:input={(event) => update("stream_name", event.currentTarget.value)} /></label>
        <label class="grid gap-1"><span class="text-xs font-semibold uppercase">Schedule</span><input class="min-h-9 rounded-md border px-3 text-sm" value={integration.schedule_cron || ""} placeholder="manual" on:input={(event) => update("schedule_cron", event.currentTarget.value)} /></label>
        <label class="grid gap-1"><span class="text-xs font-semibold uppercase">Cursor field</span><input class="min-h-9 rounded-md border px-3 text-sm" value={integration.cursor_field || ""} on:input={(event) => update("cursor_field", event.currentTarget.value)} /></label>
        <label class="inline-flex items-center gap-2"><input type="checkbox" checked={integration.enabled !== false} on:change={(event) => update("enabled", event.currentTarget.checked)} /> Enabled</label>
      </div>

      <ParamSchemaForm {schema} values={integration.params || {}} onChange={(values) => update("params", values)} />

      <div class="flex justify-end">
        <button class="min-h-9 rounded-md border border-(--color-border-strong) px-3 py-2 text-sm font-semibold text-(--color-accent-vivid)" disabled={submitting}>{submitting ? "Saving..." : "Save integration"}</button>
      </div>
    </form>
  {:else if activeTab === "history"}
    <div class="grid gap-3">
      <DataGrid columns={runColumns} rows={runs} totalCount={runs.length} currentPage={1} perPage={30} />
      {#each runs as run}
        <button type="button" class="w-fit text-sm font-semibold text-(--color-accent-vivid) hover:underline" on:click={() => openReplay(run)}>Replay {run.id}</button>
      {/each}
    </div>
  {:else}
    <LineagePanel lineage={initial.lineage} />
  {/if}

  {#if replayRun}
    <div class="fixed inset-0 z-40 grid place-items-center bg-(--color-surface-scrim) p-4">
      <div
        bind:this={replayModal}
        class="w-full max-w-xl rounded-lg border border-(--color-border-strong) bg-(--color-surface) p-4"
        role="dialog"
        aria-modal="true"
        aria-labelledby="replay-dialog-title"
        tabindex="-1"
        on:keydown={handleReplayKeydown}
      >
        <div class="mb-3 flex items-center justify-between gap-3">
          <h2 id="replay-dialog-title" class="text-lg font-semibold">Replay run</h2>
          <button bind:this={replayCloseButton} type="button" class="rounded-md border px-2 py-1 text-sm" on:click={closeReplay}>Close</button>
        </div>
        <RangePicker value={replayRange} onChange={(value, nextError) => { replayRange = value; replayError = nextError }} />
        {#if replayError}<div class="mt-3 text-sm text-(--color-danger-text)">{replayError}</div>{/if}
        <div class="mt-4 flex justify-end">
          <button type="button" class="min-h-9 rounded-md border px-3 py-2 text-sm font-semibold" disabled={Boolean(replayError)} on:click={submitReplay}>Replay</button>
        </div>
      </div>
    </div>
  {/if}
</div>
