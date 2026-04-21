<script lang="ts">
  interface Props {
    status: 'success' | 'warning' | 'danger' | 'neutral';
    label?: string;
    pulse?: boolean;
  }

  let { status, label, pulse = false }: Props = $props();

  const colorMap = {
    success: 'var(--color-success)',
    warning: 'var(--color-warning)',
    danger: 'var(--color-danger)',
    neutral: 'var(--color-neutral)'
  };
</script>

<span class="status-dot-wrap" aria-label={label}>
  <span
    class="dot"
    class:pulse={pulse && status === 'success'}
    style={`background: ${colorMap[status]}`}
  ></span>
  {#if label}
    <span class="dot-label">{label}</span>
  {/if}
</span>

<style>
  .status-dot-wrap {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }

  .dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .dot-label {
    font-size: var(--text-sm);
    color: var(--text-secondary);
  }

  .dot.pulse {
    animation: pulse-dot 2s ease-in-out infinite;
  }

  @keyframes pulse-dot {
    0%,
    100% {
      box-shadow: 0 0 0 0 transparent;
    }
    50% {
      box-shadow: 0 0 0 4px rgba(63, 185, 80, 0.2);
    }
  }

  @media (prefers-reduced-motion: reduce) {
    .dot.pulse {
      animation: none;
    }
  }
</style>
