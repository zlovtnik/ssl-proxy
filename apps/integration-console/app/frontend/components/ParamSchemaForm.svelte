<script>
  export let schema = {}
  export let values = {}
  export let onChange = () => {}

  let visibleSecrets = {}

  $: fields = Object.entries(schema || {})

  function update(key, value) {
    const field = schema[key]
    if (field?.type === "integer") {
      value = value === "" ? null : Number(value)
      if (Number.isNaN(value)) value = null
    }
    values = { ...values, [key]: value }
    onChange(values)
  }
</script>

<div class="grid gap-3 md:grid-cols-2">
  {#each fields as [key, field]}
    <label class="grid gap-1">
      <span class="text-xs font-semibold uppercase text-(--color-accent-vivid)">{field.label || key}</span>
      {#if field.type === "select"}
        <select class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-bg) px-3 text-sm" value={values[key] ?? field.default ?? ""} on:change={(event) => update(key, event.currentTarget.value)}>
          <option value="">Select</option>
          {#each field.options || [] as option}
            <option value={option}>{option}</option>
          {/each}
        </select>
      {:else if field.type === "boolean"}
        <span class="inline-flex min-h-9 items-center gap-2 rounded-md border border-(--color-control-border) bg-(--color-bg) px-3 text-sm">
          <input type="checkbox" checked={values[key] ?? field.default ?? false} on:change={(event) => update(key, event.currentTarget.checked)} />
          <span>Enabled</span>
        </span>
      {:else if field.type === "password"}
        <span class="flex gap-2">
          <input class="min-h-9 min-w-0 flex-1 rounded-md border border-(--color-control-border) bg-(--color-bg) px-3 text-sm" type={visibleSecrets[key] ? "text" : "password"} value={values[key] ?? ""} placeholder={field.placeholder || "Encrypted value"} on:input={(event) => update(key, event.currentTarget.value)} />
          <button type="button" class="min-h-9 rounded-md border border-(--color-border-muted) px-3 text-sm" on:click={() => visibleSecrets = { ...visibleSecrets, [key]: !visibleSecrets[key] }}>{visibleSecrets[key] ? "Hide" : "Show"}</button>
        </span>
      {:else}
        <input class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-bg) px-3 text-sm" type={field.type === "integer" ? "number" : field.type === "date" ? "date" : "text"} value={values[key] ?? field.default ?? ""} min={field.min} max={field.max} placeholder={field.placeholder || ""} on:input={(event) => update(key, event.currentTarget.value)} />
      {/if}
    </label>
  {:else}
    <div class="text-sm text-(--color-text-muted)">No parameters for this type.</div>
  {/each}
</div>
