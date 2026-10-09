/**
 * Scroll-triggered count-up for operator peak figures.
 * SSR emits the exact final en-GB string; animation is progressive enhancement
 * and always settles back to that same string. Skipped under reduced motion.
 */
import { createSignal, onMount } from 'solid-js';

const number = new Intl.NumberFormat('en-GB', { maximumFractionDigits: 2 });

const finalText = (value: number) => `${number.format(value)} records`;

function motionReduced() {
  return (
    window.matchMedia('(prefers-reduced-motion: reduce)').matches ||
    document.documentElement.dataset.motion === 'reduced'
  );
}

export default function OctopusCountUp(props: { value: number }) {
  const final = finalText(props.value);
  const [text, setText] = createSignal(final);

  onMount(() => {
    if (motionReduced() || props.value <= 0) return;
    let frame = 0;
    const duration = 850;
    const target = props.value;
    const startValue = 0;
    const tick = (now: number, start: number) => {
      const t = Math.min(1, (now - start) / duration);
      const eased = 1 - Math.pow(1 - t, 3);
      const current = Math.round(startValue + (target - startValue) * eased);
      setText(t >= 1 ? final : `${number.format(current)} records`);
      if (t < 1) frame = requestAnimationFrame((n) => tick(n, start));
    };
    // Start from zero only once the island is live so SSR text is never wrong.
    setText(`${number.format(0)} records`);
    frame = requestAnimationFrame((now) => tick(now, now));
    return () => cancelAnimationFrame(frame);
  });

  return <span data-ux="count-up">{text()}</span>;
}
