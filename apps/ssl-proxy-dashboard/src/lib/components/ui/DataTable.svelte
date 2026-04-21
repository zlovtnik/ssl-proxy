<script lang="ts">
  export interface DataTableColumn {
    key: string;
    label: string;
    align?: 'left' | 'right';
    format?: (value: unknown, row: Record<string, unknown>) => string;
  }

  interface Props {
    columns: DataTableColumn[];
    rows: Record<string, unknown>[];
    loading?: boolean;
    emptyText?: string;
    caption?: string;
  }

  let { columns, rows, loading = false, emptyText = 'No rows', caption }: Props = $props();
</script>

<div class="table-wrap" role="region" aria-live="polite">
  <table>
    {#if caption}
      <caption class="sr-only">{caption}</caption>
    {/if}
    <thead>
      <tr>
        {#each columns as column}
          <th class:align-right={column.align === 'right'}>{column.label}</th>
        {/each}
      </tr>
    </thead>
    <tbody>
      {#if loading}
        <tr>
          <td colspan={columns.length} class="state">Loading…</td>
        </tr>
      {:else if rows.length === 0}
        <tr>
          <td colspan={columns.length} class="state">{emptyText}</td>
        </tr>
      {:else}
        {#each rows as row}
          <tr>
            {#each columns as column}
              <td class:align-right={column.align === 'right'}>
                {column.format
                  ? column.format(row[column.key], row)
                  : String(row[column.key] ?? '—')}
              </td>
            {/each}
          </tr>
        {/each}
      {/if}
    </tbody>
  </table>
</div>

<style>
  .table-wrap {
    overflow: auto;
    border-radius: var(--radius-md);
    border: 1px solid var(--border-subtle);
  }

  table {
    width: 100%;
    border-collapse: collapse;
    min-width: 560px;
  }

  th,
  td {
    text-align: left;
    padding: var(--space-2) var(--space-3);
    border-bottom: 1px solid var(--border-subtle);
    white-space: nowrap;
  }

  th {
    background: color-mix(in oklab, var(--bg-surface) 92%, transparent);
    color: var(--text-secondary);
    font-size: var(--text-xs);
    letter-spacing: 0.04em;
    text-transform: uppercase;
    position: sticky;
    top: 0;
    z-index: 1;
  }

  tr:hover td {
    background: color-mix(in oklab, var(--bg-elevated) 85%, transparent);
  }

  td {
    font-size: var(--text-md);
  }

  .state {
    color: var(--text-secondary);
    text-align: center;
    padding: var(--space-6);
  }

  .align-right {
    text-align: right;
  }
</style>
