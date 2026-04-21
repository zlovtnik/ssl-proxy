import { describe, expect, it } from 'vitest';
import { riskBarColor, VERDICT_STYLES } from '$lib/utils/color';

describe('color utils', () => {
  it('maps verdict labels', () => {
    expect(VERDICT_STYLES.BLOCKED.label).toBe('Blocked');
    expect(VERDICT_STYLES.TARPIT.label).toBe('Tarpit');
  });

  it('maps risk score bands', () => {
    expect(riskBarColor(10)).toBe('var(--color-neutral)');
    expect(riskBarColor(20_000)).toBe('var(--color-warning)');
    expect(riskBarColor(200_000)).toBe('var(--verdict-aggressive)');
    expect(riskBarColor(2_000_000)).toBe('var(--color-danger)');
  });
});
