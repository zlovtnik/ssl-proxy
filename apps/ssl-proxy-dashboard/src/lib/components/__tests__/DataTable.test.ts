import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import DataTable from '$lib/components/ui/DataTable.svelte';

describe('DataTable', () => {
  it('renders empty and loading states', async () => {
    const columns = [{ key: 'name', label: 'Name' }];

    const { rerender } = render(DataTable, {
      columns,
      rows: [],
      loading: false,
      emptyText: 'No rows available'
    });

    expect(screen.getByText('No rows available')).toBeInTheDocument();

    await rerender({ columns, rows: [], loading: true, emptyText: 'No rows available' });
    expect(screen.getByText('Loading…')).toBeInTheDocument();
  });
});
