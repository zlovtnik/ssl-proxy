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

<form class="mb-4 rounded-lg border border-[var(--color-border-muted)] bg-[var(--color-surface)] p-3" on:submit={submit}>
  <div class="mb-3 flex flex-wrap items-center justify-between gap-3">
    <h2 class="text-lg font-semibold text-[var(--color-text)]">{title}</h2>
    <button
      type="button"
      class="min-h-8 rounded-md border border-[var(--color-border-muted)] bg-[var(--color-bg)] px-3 py-1.5 text-sm font-semibold text-[var(--color-accent-vivid)] hover:bg-[var(--color-accent-surface)]"
      on:click={onCancel}
    >
      {cancelLabel}
    </button>
  </div>

  {#if errors.length}
    <div class="mb-3 rounded-md border border-[var(--color-danger-border)] bg-[var(--color-danger-surface)] px-3 py-2 text-sm text-[var(--color-danger-text)]" role="alert">
      {errors.join(", ")}
    </div>
  {/if}

  <div class="grid gap-3 md:grid-cols-2">
    {#each fields as field}
      <label class={field.type === "textarea" ? "grid gap-1 md:col-span-2" : "grid gap-1"}>
        <span class="text-xs font-semibold uppercase tracking-wide text-[var(--color-accent-vivid)]">{field.label}</span>
        {#if field.type === "textarea"}
          <textarea
            class="min-h-24 rounded-md border border-[var(--color-control-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-faint)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-focus)]"
            value={record[field.key] || ""}
            placeholder={field.placeholder || ""}
            on:input={(event) => updateField(field.key, event.currentTarget.value)}
          ></textarea>
        {:else if field.type === "checkbox"}
          <span class="inline-flex min-h-9 items-center gap-2 rounded-md border border-[var(--color-control-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text)]">
            <input type="checkbox" checked={Boolean(record[field.key])} on:change={(event) => updateField(field.key, event.currentTarget.checked)} />
            <span>{field.checkboxLabel || "Enabled"}</span>
          </span>
        {:else}
          <input
            class="min-h-9 rounded-md border border-[var(--color-control-border)] bg-[var(--color-bg)] px-3 py-2 text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-faint)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-focus)]"
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
      class="min-h-9 rounded-md border border-[var(--color-border-strong)] bg-[var(--color-bg)] px-3 py-2 text-sm font-semibold text-[var(--color-accent-vivid)] hover:bg-[var(--color-accent-surface)] disabled:cursor-not-allowed disabled:border-[var(--color-border-muted)] disabled:text-[var(--color-text-faint)] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--color-focus)]"
      disabled={submitting}
    >
      {submitting ? "Saving..." : submitLabel}
    </button>
  </div>
</form>
