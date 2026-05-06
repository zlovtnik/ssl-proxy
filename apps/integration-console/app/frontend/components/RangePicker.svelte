<script>
  let { value = { range_type: "cursor", from_value: "", to_value: "" }, onChange = () => {} } = $props()

  const initialRange = () => value || { range_type: "cursor", from_value: "", to_value: "" }

  let rangeType = $state(initialRange()?.range_type || "cursor")
  let fromValue = $state(initialRange()?.from_value || "")
  let toValue = $state(initialRange()?.to_value || "")
  let lastSyncedValue = $state(initialRange())
  let error = $derived(rangeError(rangeType, fromValue, toValue))
  let preview = $derived(`${fromValue || "current cursor"} -> ${toValue || "now"}`)

  $effect(() => {
    if (value === lastSyncedValue) return

    lastSyncedValue = value
    rangeType = value?.range_type || "cursor"
    fromValue = value?.from_value || ""
    toValue = value?.to_value || ""
  })

  function update(patch) {
    rangeType = patch.range_type ?? rangeType
    fromValue = patch.from_value ?? fromValue
    toValue = patch.to_value ?? toValue

    const nextValue = { range_type: rangeType, from_value: fromValue, to_value: toValue }
    onChange(nextValue, rangeError(rangeType, fromValue, toValue))
  }

  function applyPreset(hours) {
    const to = new Date()
    const from = new Date(to.getTime() - hours * 60 * 60 * 1000)
    update({ range_type: "datetime", from_value: toLocalInput(from), to_value: toLocalInput(to) })
  }

  function rangeError(type, from, to) {
    if (type !== "datetime" || !from || !to) return ""
    const fromTime = new Date(from).getTime()
    const toTime = new Date(to).getTime()
    if (Number.isNaN(fromTime)) return "Invalid From date."
    if (Number.isNaN(toTime)) return "Invalid To date."
    return fromTime < toTime ? "" : "From must be before To."
  }

  function toLocalInput(date) {
    const offset = date.getTimezoneOffset() * 60000
    return new Date(date.getTime() - offset).toISOString().slice(0, 16)
  }
</script>

<div class="grid gap-3 rounded-md border border-(--color-border-muted) bg-(--color-bg) p-3">
  <div class="flex flex-wrap items-center gap-2">
    <label class="grid gap-1">
      <span class="text-xs font-semibold uppercase text-(--color-text-muted)">Range type</span>
      <select class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-surface) px-3 text-sm" value={rangeType} onchange={(event) => update({ range_type: event.currentTarget.value })}>
        <option value="cursor">Cursor</option>
        <option value="datetime">Date</option>
      </select>
    </label>
    <button type="button" class="min-h-8 rounded-md border border-(--color-border-muted) px-2 text-sm" onclick={() => applyPreset(1)}>Last hour</button>
    <button type="button" class="min-h-8 rounded-md border border-(--color-border-muted) px-2 text-sm" onclick={() => applyPreset(24)}>Last 24h</button>
    <button type="button" class="min-h-8 rounded-md border border-(--color-border-muted) px-2 text-sm" onclick={() => applyPreset(168)}>Last 7d</button>
  </div>

  <div class="grid gap-3 md:grid-cols-2">
    <label class="grid gap-1">
      <span class="text-xs font-semibold uppercase text-(--color-text-muted)">From</span>
      <input class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-surface) px-3 text-sm" type={rangeType === "datetime" ? "datetime-local" : "text"} value={fromValue} placeholder="current cursor" oninput={(event) => update({ from_value: event.currentTarget.value })} />
    </label>
    <label class="grid gap-1">
      <span class="text-xs font-semibold uppercase text-(--color-text-muted)">To</span>
      <input class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-surface) px-3 text-sm" type={rangeType === "datetime" ? "datetime-local" : "text"} value={toValue} placeholder="now" oninput={(event) => update({ to_value: event.currentTarget.value })} />
    </label>
  </div>

  <div class="text-sm text-(--color-text-muted)">Preview: {preview}</div>
  {#if error}
    <div class="text-sm font-semibold text-(--color-danger-text)" role="alert">{error}</div>
  {/if}
</div>
