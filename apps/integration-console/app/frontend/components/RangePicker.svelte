<script>
  export let value = { range_type: "cursor", from_value: "", to_value: "" }
  export let onChange = () => {}

  $: rangeType = value.range_type || "cursor"
  $: fromValue = value.from_value || ""
  $: toValue = value.to_value || ""
  $: error = rangeError(rangeType, fromValue, toValue)
  $: preview = `${fromValue || "current cursor"} -> ${toValue || "now"}`

  function update(patch) {
    value = { ...value, ...patch }
    onChange(value, error)
  }

  function applyPreset(hours) {
    const to = new Date()
    const from = new Date(to.getTime() - hours * 60 * 60 * 1000)
    update({ range_type: "datetime", from_value: toLocalInput(from), to_value: toLocalInput(to) })
  }

  function rangeError(type, from, to) {
    if (type !== "datetime" || !from || !to) return ""
    return new Date(from).getTime() < new Date(to).getTime() ? "" : "From must be before To."
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
      <select class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-surface) px-3 text-sm" value={rangeType} on:change={(event) => update({ range_type: event.currentTarget.value })}>
        <option value="cursor">Cursor</option>
        <option value="datetime">Date</option>
      </select>
    </label>
    <button type="button" class="min-h-8 rounded-md border border-(--color-border-muted) px-2 text-sm" on:click={() => applyPreset(1)}>Last hour</button>
    <button type="button" class="min-h-8 rounded-md border border-(--color-border-muted) px-2 text-sm" on:click={() => applyPreset(24)}>Last 24h</button>
    <button type="button" class="min-h-8 rounded-md border border-(--color-border-muted) px-2 text-sm" on:click={() => applyPreset(168)}>Last 7d</button>
  </div>

  <div class="grid gap-3 md:grid-cols-2">
    <label class="grid gap-1">
      <span class="text-xs font-semibold uppercase text-(--color-text-muted)">From</span>
      <input class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-surface) px-3 text-sm" type={rangeType === "datetime" ? "datetime-local" : "text"} value={fromValue} placeholder="current cursor" on:input={(event) => update({ from_value: event.currentTarget.value })} />
    </label>
    <label class="grid gap-1">
      <span class="text-xs font-semibold uppercase text-(--color-text-muted)">To</span>
      <input class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-surface) px-3 text-sm" type={rangeType === "datetime" ? "datetime-local" : "text"} value={toValue} placeholder="now" on:input={(event) => update({ to_value: event.currentTarget.value })} />
    </label>
  </div>

  <div class="text-sm text-(--color-text-muted)">Preview: {preview}</div>
  {#if error}
    <div class="text-sm font-semibold text-(--color-danger-text)" role="alert">{error}</div>
  {/if}
</div>
