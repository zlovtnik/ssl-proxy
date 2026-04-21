import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import MetricCard from '$lib/components/ui/MetricCard.svelte';

describe('MetricCard', () => {
  it('renders label and value', () => {
    render(MetricCard, { label: 'Blocked', value: '42', color: 'danger' });

    expect(screen.getByText('Blocked')).toBeInTheDocument();
    expect(screen.getByText('42')).toBeInTheDocument();
  });
});
