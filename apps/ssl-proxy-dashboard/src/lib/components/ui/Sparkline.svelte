<script lang="ts">
  interface Props {
    points: number[];
    width?: number;
    height?: number;
    stroke?: string;
  }

  let { points, width = 160, height = 44, stroke = 'var(--color-info)' }: Props = $props();

  const path = $derived.by(() => {
    if (!points.length) return '';

    const max = Math.max(...points, 1);
    const min = Math.min(...points, 0);
    const range = Math.max(max - min, 1);

    return points
      .map((value, index) => {
        const x = (index / Math.max(points.length - 1, 1)) * width;
        const y = height - ((value - min) / range) * (height - 4) - 2;
        return `${index === 0 ? 'M' : 'L'}${x.toFixed(2)} ${y.toFixed(2)}`;
      })
      .join(' ');
  });
</script>

<svg viewBox={`0 0 ${width} ${height}`} aria-hidden="true" focusable="false">
  <path d={path} fill="none" stroke={stroke} stroke-width="2" stroke-linecap="round" />
</svg>

<style>
  svg {
    width: 100%;
    height: auto;
    display: block;
  }
</style>
