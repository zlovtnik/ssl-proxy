import { describe, expect, it } from 'vitest';
import { formatBytes, formatDuration, formatHz } from '$lib/utils/format';

describe('format utils', () => {
  it('formats bytes at multiple magnitudes', () => {
    expect(formatBytes(120)).toBe('120 B');
    expect(formatBytes(2_048)).toBe('2.0 KB');
    expect(formatBytes(1_048_576)).toBe('1.0 MB');
  });

  it('formats frequency', () => {
    expect(formatHz(2.25)).toBe('2.25 Hz');
    expect(formatHz(0.02)).toBe('20 mHz');
  });

  it('formats duration', () => {
    expect(formatDuration(300)).toBe('300ms');
    expect(formatDuration(8_400)).toBe('8.4s');
    expect(formatDuration(130_000)).toBe('2m 10s');
  });
});
