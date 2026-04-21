import { render, screen } from '@testing-library/svelte';
import { describe, expect, it } from 'vitest';
import HostRow from '$lib/components/hosts/HostRow.svelte';

describe('HostRow', () => {
  it('renders host and verdict data', () => {
    render(HostRow, {
      host: {
        host: 'api.example.com',
        blocked_attempts: 12,
        blocked_bytes_approx: 4096,
        frequency_hz: 2.5,
        risk_score: 10000,
        verdict: 'AGGRESSIVE_POLLING',
        tarpit_held_ms: 0,
        battery_saved_mwh: 0,
        category: 'api',
        consecutive_blocks: 2,
        last_reason: 'rate-limit'
      }
    });

    expect(screen.getByText('api.example.com')).toBeInTheDocument();
    expect(screen.getByText('Aggressive')).toBeInTheDocument();
  });
});
