<article class="relative overflow-hidden rounded-lg border border-(--color-border-muted) border-l-4 border-l-(--color-border) bg-(--color-surface) p-4" aria-busy="true">
  <div class="flex items-start justify-between gap-3">
    <div class="w-full">
      <slot name="label" />
      <div class="mt-3 h-8 w-24 rounded bg-(--color-border-muted)"></div>
      <div class="mt-3 h-4 w-32 rounded bg-(--color-border-muted)"></div>
    </div>
    <slot name="icon" />
  </div>
  <div class="mt-3 h-8 w-full rounded bg-(--color-border-muted)"></div>
  <div class="skeleton-shimmer absolute inset-0" aria-hidden="true"></div>
</article>
