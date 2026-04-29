<script>
  export let title = ""
  export let fields = []
  export let record = {}
  export let errors = []
  export let submitting = false
  export let submitLabel = "Save"
  export let cancelLabel = "Cancel"
  export let onSubmit = () => {}
  export let onCancel = () => {}

  function submit(event) {
    event.preventDefault()
    onSubmit(record)
  }

  function updateField(key, value) {
    record[key] = value
    record = { ...record }
  }
</script>

<form class="mb-4 rounded-lg border border-[#1f3320] bg-[#111a11] p-3" on:submit={submit}>
  <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
    <h2 class="text-lg font-semibold text-[#c8e6c8]">{title}</h2>
    <button
      type="button"
      class="min-h-8 rounded-md border border-[#1f3320] bg-[#0d130d] px-3 py-1.5 text-sm font-semibold text-[#86efac] hover:bg-[#0f2d0f]"
      on:click={onCancel}
    >
      {cancelLabel}
    </button>
  </div>

  {#if errors.length}
    <div class="mb-3 rounded-md border border-[#7f1d1d] bg-[#190d0d] px-3 py-2 text-sm text-[#fecaca]" role="alert">
      {errors.join(", ")}
    </div>
  {/if}

  <div class="grid gap-3 md:grid-cols-2">
    {#each fields as field}
      <label class={field.type === "textarea" ? "grid gap-1 md:col-span-2" : "grid gap-1"}>
        <span class="text-xs font-semibold uppercase tracking-wide text-[#86efac]">{field.label}</span>
        {#if field.type === "textarea"}
          <textarea
            class="min-h-24 rounded-md border border-[#2d4a2d] bg-[#0d130d] px-3 py-2 text-sm text-[#c8e6c8] placeholder:text-[#4d7a4d] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#fbbf24]"
            value={record[field.key] || ""}
            placeholder={field.placeholder || ""}
            on:input={(event) => updateField(field.key, event.currentTarget.value)}
          ></textarea>
        {:else if field.type === "checkbox"}
          <span class="inline-flex min-h-9 items-center gap-2 rounded-md border border-[#2d4a2d] bg-[#0d130d] px-3 py-2 text-sm text-[#c8e6c8]">
            <input type="checkbox" checked={Boolean(record[field.key])} on:change={(event) => updateField(field.key, event.currentTarget.checked)} />
            <span>{field.checkboxLabel || "Enabled"}</span>
          </span>
        {:else}
          <input
            class="min-h-9 rounded-md border border-[#2d4a2d] bg-[#0d130d] px-3 py-2 text-sm text-[#c8e6c8] placeholder:text-[#4d7a4d] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#fbbf24]"
            type={field.type || "text"}
            value={record[field.key] || ""}
            placeholder={field.placeholder || ""}
            on:input={(event) => updateField(field.key, event.currentTarget.value)}
          />
        {/if}
      </label>
    {/each}
  </div>

  <div class="mt-4 flex justify-end">
    <button
      type="submit"
      class="min-h-9 rounded-md border border-[#1f6b1f] bg-[#0d130d] px-3 py-2 text-sm font-semibold text-[#86efac] hover:bg-[#0f2d0f] disabled:cursor-not-allowed disabled:border-[#1f3320] disabled:text-[#4d7a4d] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#fbbf24]"
      disabled={submitting}
    >
      {submitting ? "Saving..." : submitLabel}
    </button>
  </div>
</form>
