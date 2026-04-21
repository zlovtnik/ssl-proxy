import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import VerdictBadge from '$lib/components/hosts/VerdictBadge.svelte';

describe('VerdictBadge', () => {
  it('renders mapped verdict label', () => {
    render(VerdictBadge, { verdict: 'HEURISTIC_FLAG_DATA_EXFIL' });

    expect(screen.getByText('Data Exfil')).toBeInTheDocument();
  });
});
