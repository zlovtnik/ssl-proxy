<script>
  import { onMount } from "svelte"
  import DataGrid from "../components/DataGrid.svelte"
  import RangePicker from "../components/RangePicker.svelte"
  import consumer from "../../javascript/channels/consumer"
  import { requestJson, errorMessages } from "../lib/api"

  export let initial = {}

  let run = initial.run || {}
  let batches = initial.batches || []
  let expanded = new Set()
  let error = ""
  let rerunOpen = false
  let rerunRange = { range_type: run.range_type || "cursor", from_value: run.from_value || "", to_value: run.to_value || "" }
  let rerunError = ""

  const endpoints = initial.endpoints || {}

  const columns = [
    { key: "batch_no", label: "Batch", size: "sm" },
    { key: "status", label: "Status", size: "sm" },
    { key: "range", label: "Range", format: (_value, row) => `${row.from_value || ""} -> ${row.to_value || ""}`, size: "lg" },
    { key: "rows", label: "Rows R/W/E", format: (_value, row) => `${row.rows_read || 0}/${row.rows_written || 0}/${row.rows_errored || 0}`, size: "md" },
    { key: "duration_ms", label: "Duration", format: (value) => value == null ? "-" : `${value}ms`, size: "sm" },
    { key: "error_detail", label: "Error", format: (value) => value ? "Open" : "-", size: "sm" }
  ]

  $: totalDuration = run.duration_seconds == null ? "-" : `${run.duration_seconds}s`
  $: gantt = ganttBars(batches)

  onMount(() => {
    const subscription = consumer.subscriptions.create(
      { channel: "IntegrationRunChannel", run_id: run.id },
      {
        received(data) {
          if (data.run) run = { ...run, ...data.run }
          if (data.batch) upsertBatch(data.batch)
        }
      }
    )
    const timer = window.setInterval(fetchBatches, 10000)
    return () => {
      consumer.subscriptions.remove(subscription)
      window.clearInterval(timer)
    }
  })

  async function fetchBatches() {
    if (!endpoints.batches) return
    try {
      const payload = await requestJson(endpoints.batches)
      if (payload.run) run = { ...run, ...payload.run }
      batches = payload.batches || []
    } catch {
      // The run page remains useful even when sync DB polling is temporarily unavailable.
    }
  }

  function upsertBatch(batch) {
    const index = batches.findIndex((row) => row.id === batch.id)
    if (index === -1) batches = [...batches, batch]
    else batches = batches.map((row, rowIndex) => rowIndex === index ? { ...row, ...batch } : row)
  }

  function toggle(id) {
    expanded.has(id) ? expanded.delete(id) : expanded.add(id)
    expanded = new Set(expanded)
  }

  async function cancelRun() {
    error = ""
    try {
      const payload = await requestJson(endpoints.cancel, { method: "POST" })
      run = payload.run
    } catch (requestError) {
      error = errorMessages(requestError).join(", ")
    }
  }

  async function rerun() {
    if (rerunError) return
    const url = run.integration_url ? `${run.integration_url}/trigger` : null
    if (!url) {
      rerunError = "Integration URL is not available"
      return
    }
    try {
      const payload = await requestJson(url, { method: "POST", body: { integration_run: rerunRange } })
      if (typeof payload.redirectUrl === "string" && payload.redirectUrl.length > 0) {
        window.location.href = payload.redirectUrl
      } else {
        rerunError = "Missing redirect URL in response"
      }
    } catch (requestError) {
      rerunError = errorMessages(requestError).join(", ")
    }
  }

  function ganttBars(rows) {
    const width = 520
    if (!rows.length) return []
    const each = width / rows.length
    return rows.map((row, index) => ({ ...row, x: index * each, width: Math.max(each - 3, 2) }))
  }

  function statusFill(status) {
    if (status === "failed") return "fill-(--color-danger-text)"
    if (status === "running" || status === "processing" || status === "dispatched") return "fill-(--color-accent)"
    if (status === "completed") return "fill-(--color-accent-vivid)"
    return "fill-(--color-border)"
  }
</script>

<div class="grid gap-4">
  <div class="flex flex-wrap items-center justify-between gap-3">
    <div>
      <h1 class="text-2xl font-bold text-(--color-text)">Run {run.id}</h1>
      <a class="text-sm text-(--color-accent-vivid) hover:underline" href={run.integration_url}>{run.integration_name}</a>
    </div>
    <a class="text-sm font-semibold text-(--color-accent-vivid) hover:underline" href="/integration_runs">All runs</a>
  </div>

  {#if error}<div class="rounded-md border border-(--color-danger-border) bg-(--color-danger-surface) px-3 py-2 text-sm text-(--color-danger-text)">{error}</div>{/if}

  <div class="grid gap-3 md:grid-cols-4">
    <article class="rounded-lg border border-(--color-border-muted) bg-(--color-surface) p-4"><div class="text-xs uppercase text-(--color-text-muted)">Status</div><div class="mt-2 text-2xl font-bold">{run.status}</div></article>
    <article class="rounded-lg border border-(--color-border-muted) bg-(--color-surface) p-4"><div class="text-xs uppercase text-(--color-text-muted)">Duration</div><div class="mt-2 text-2xl font-bold">{totalDuration}</div></article>
    <article class="rounded-lg border border-(--color-border-muted) bg-(--color-surface) p-4"><div class="text-xs uppercase text-(--color-text-muted)">Rows R/W/E</div><div class="mt-2 text-2xl font-bold">{run.rows_read || 0}/{run.rows_written || 0}/{run.rows_errored || 0}</div></article>
    <article class="rounded-lg border border-(--color-border-muted) bg-(--color-surface) p-4"><div class="text-xs uppercase text-(--color-text-muted)">Range</div><div class="mt-2 text-sm font-semibold">{run.from_value || "current"} -> {run.to_value || "now"}</div></article>
  </div>

  <div class="flex flex-wrap gap-2">
    <button type="button" class="min-h-9 rounded-md border px-3 py-2 text-sm font-semibold" disabled={!endpoints.cancel} on:click={cancelRun}>Cancel</button>
    <button type="button" class="min-h-9 rounded-md border px-3 py-2 text-sm font-semibold" on:click={() => rerunOpen = true}>Re-run</button>
    <a class="min-h-9 rounded-md border px-3 py-2 text-sm font-semibold" href={`data:text/csv;charset=utf-8,${encodeURIComponent(batches.filter((row) => row.error_detail).map((row) => `${row.batch_no},"${String(row.error_detail).replaceAll('"', '""')}"`).join("\n"))}`} download={`integration-run-${run.id}-errors.csv`}>Download error log</a>
  </div>

  <div class="rounded-lg border border-(--color-border-muted) bg-(--color-surface) p-3">
    <svg class="h-20 w-full" viewBox="0 0 540 80" aria-label="Batch timeline">
      {#each gantt as bar}
        <rect x={bar.x + 10} y="24" width={bar.width} height="28" class={statusFill(bar.status)} />
      {/each}
    </svg>
  </div>

  <DataGrid {columns} rows={batches} totalCount={batches.length} currentPage={1} perPage={Math.max(batches.length, 1)} />
  <div class="grid gap-2">
    {#each batches as batch}
      {#if batch.error_detail}
        <button type="button" class="w-fit text-sm font-semibold text-(--color-accent-vivid) hover:underline" on:click={() => toggle(batch.id)}>Batch {batch.batch_no} error detail</button>
        {#if expanded.has(batch.id)}
          <pre class="overflow-auto rounded-md border border-(--color-border-muted) bg-(--color-bg) p-3 text-xs">{batch.error_detail}</pre>
        {/if}
      {/if}
    {/each}
  </div>

  {#if rerunOpen}
    <div class="fixed inset-0 z-40 grid place-items-center bg-(--color-surface-scrim) p-4">
      <div class="w-full max-w-xl rounded-lg border border-(--color-border-strong) bg-(--color-surface) p-4">
        <div class="mb-3 flex items-center justify-between gap-3">
          <h2 class="text-lg font-semibold">Re-run</h2>
          <button type="button" class="rounded-md border px-2 py-1 text-sm" on:click={() => rerunOpen = false}>Close</button>
        </div>
        <RangePicker value={rerunRange} onChange={(value, nextError) => { rerunRange = value; rerunError = nextError }} />
        {#if rerunError}<div class="mt-3 text-sm text-(--color-danger-text)">{rerunError}</div>{/if}
        <div class="mt-4 flex justify-end">
          <button type="button" class="min-h-9 rounded-md border px-3 py-2 text-sm font-semibold" disabled={Boolean(rerunError)} on:click={rerun}>Run again</button>
        </div>
      </div>
    </div>
  {/if}
</div>
