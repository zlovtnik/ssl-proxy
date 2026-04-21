import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import DashboardPage from '../+page.svelte';
import HostsPage from '../hosts/+page.svelte';
import PeersPage from '../peers/+page.svelte';

describe('route smoke coverage', () => {
  it('renders route headings', () => {
    render(DashboardPage);
    expect(screen.getByRole('heading', { name: 'Real-time Command Center', level: 1 })).toBeInTheDocument();

    render(HostsPage);
    expect(screen.getByRole('heading', { name: 'Host Heat Map', level: 1 })).toBeInTheDocument();

    render(PeersPage);
    expect(screen.getByRole('heading', { name: 'Peer Telemetry', level: 1 })).toBeInTheDocument();
  });
});
