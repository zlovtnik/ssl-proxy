<script>
  import IdentitiesFilter from "../components/IdentitiesFilter.svelte"

  export let initial = {}

  function handleFilterChange(filters, meta) {
    if (meta?.serialized) {
      const url = new URL(window.location)
      url.searchParams.set('filters', meta.serialized)
      url.searchParams.delete('page')
      window.location.href = url.toString()
    }
  }
</script>

<div class="mb-4">
  <IdentitiesFilter onFilterChange={handleFilterChange} initialFilters={initial.filters || []} />
</div>
