<script>
  export let row = {}
  export let onEdit = () => {}
  export let onDelete = () => {}
  export let deleteLabel = "Remove"
</script>

<div class="flex flex-wrap items-center gap-2">
  <button
    type="button"
    class="min-h-8 rounded-md border border-(--color-border-strong) bg-(--color-bg) px-2 py-1 text-sm font-semibold text-(--color-accent-vivid) hover:bg-(--color-accent-surface) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
    on:click={() => onEdit(row)}
  >
    Edit
  </button>
  <button
    type="button"
    class="min-h-8 rounded-md border border-(--color-danger-border) bg-(--color-danger-surface) px-2 py-1 text-sm font-semibold text-(--color-danger-text) hover:bg-(--color-danger-surface-hover) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
    on:click={() => onDelete(row)}
  >
    {deleteLabel}
  </button>
</div>
