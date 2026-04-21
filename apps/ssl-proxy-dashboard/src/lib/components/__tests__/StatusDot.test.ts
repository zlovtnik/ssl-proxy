import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import StatusDot from '$lib/components/ui/StatusDot.svelte';

describe('StatusDot', () => {
  it('renders label and status dot wrapper', () => {
    render(StatusDot, { status: 'success', label: 'Live', pulse: true });

    expect(screen.getByText('Live')).toBeInTheDocument();
  });
});
