<script lang="ts">
  import type { HostSnapshot } from '$lib/types';
  import VerdictBadge from './VerdictBadge.svelte';
  import { formatBytes, formatHz, formatNumber } from '$lib/utils/format';
  import { clamp } from '$lib/utils/format';
  import { riskBarColor } from '$lib/utils/color';

  interface Props {
    host: HostSnapshot;
    maxRisk?: number;
  }

  let { host, maxRisk = 1_000_000 }: Props = $props();

  const riskWidth = $derived(clamp((host.risk_score / maxRisk) * 100, 0, 100));
</script>

<tr>
  <td class="host">{host.host}</td>
  <td>{formatNumber(host.blocked_attempts)}</td>
  <td>{formatHz(host.frequency_hz)}</td>
  <td>{formatBytes(host.blocked_bytes_approx)}</td>
  <td>
    <div class="risk-bar-wrap" title={String(host.risk_score)}>
      <div
        class="risk-bar"
        style={`width:${riskWidth}%; background:${riskBarColor(host.risk_score)}`}
      ></div>
    </div>
  </td>
  <td><VerdictBadge verdict={host.verdict} /></td>
  <td class="reason">{host.last_reason ?? '—'}</td>
</tr>

<style>
  .host {
    font-weight: var(--weight-medium);
    max-width: 280px;
    text-overflow: ellipsis;
    overflow: hidden;
  }

  .reason {
    color: var(--text-secondary);
  }

  .risk-bar-wrap {
    width: 96px;
    height: 8px;
    background: #1e2a35;
    border-radius: var(--radius-full);
    overflow: hidden;
  }

  .risk-bar {
    height: 100%;
    border-radius: var(--radius-full);
    transition: width 0.25s ease;
  }
</style>
