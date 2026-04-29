<script>
  export let row = {}
  export let onEdit = () => {}
  export let onDelete = () => {}
  export let deleteLabel = "Remove"
</script>

<div class="flex flex-wrap items-center gap-2">
  <button
    type="button"
    class="min-h-8 rounded-md border border-[#1f6b1f] bg-[#0d130d] px-2 py-1 text-sm font-semibold text-[#86efac] hover:bg-[#0f2d0f] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#fbbf24]"
    on:click={() => onEdit(row)}
  >
    Edit
  </button>
  <button
    type="button"
    class="min-h-8 rounded-md border border-[#7f1d1d] bg-[#190d0d] px-2 py-1 text-sm font-semibold text-[#fecaca] hover:bg-[#2a1111] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#fbbf24]"
    on:click={() => onDelete(row)}
  >
    {deleteLabel}
  </button>
</div>
