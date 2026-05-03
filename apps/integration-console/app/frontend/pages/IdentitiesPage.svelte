<script>
  import IdentitiesFilter from "../components/IdentitiesFilter.svelte"

  export let initial = {}

  function handleFilterChange(filters, meta) {
    const url = new URL(window.location)
    if (meta?.serialized) {
      url.searchParams.set('filters', meta.serialized)
    } else {
      url.searchParams.delete('filters')
    }
    url.searchParams.delete('page')
    window.location.href = url.toString()
  }
</script>

<div class="mb-4">
  <IdentitiesFilter onFilterChange={handleFilterChange} initialFilters={initial.filters || []} />
</div>
