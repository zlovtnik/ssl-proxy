<script>
  export let rows = 5
  export let columns = 3
</script>

{#each Array(rows) as _, rowIndex}
  <tr>
    {#each Array(columns) as _, columnIndex}
      <td>
        <div class="relative h-4 overflow-hidden rounded bg-(--color-border-muted)" aria-hidden="true">
          <div class="skeleton-shimmer absolute inset-0"></div>
        </div>
        {#if rowIndex === 0 && columnIndex === 0}
          <span class="sr-only">Loading rows</span>
        {/if}
      </td>
    {/each}
  </tr>
{/each}
