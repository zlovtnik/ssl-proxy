<script lang="ts">
  import type { Verdict } from '$lib/types';
  import { VERDICT_STYLES } from '$lib/utils/color';

  interface Props {
    verdict: Verdict;
  }

  let { verdict }: Props = $props();

  const style = $derived(VERDICT_STYLES[verdict] ?? VERDICT_STYLES.BLOCKED);
</script>

<span class="verdict-badge" style={`color: ${style.color}; background: ${style.bg}`} title={verdict}>
  {style.label}
</span>

<style>
  .verdict-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    font-size: var(--text-xs);
    font-weight: var(--weight-medium);
    letter-spacing: 0.04em;
    text-transform: uppercase;
    white-space: nowrap;
  }
</style>
