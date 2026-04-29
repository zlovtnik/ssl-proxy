<script>
  export let row = {}
  export let onRetry = () => {}
  export let disabled = false
</script>

<button
  type="button"
  class="min-h-8 rounded-md border border-[#1f6b1f] bg-[#0d130d] px-2 py-1 text-sm font-semibold text-[#86efac] hover:bg-[#0f2d0f] disabled:cursor-not-allowed disabled:border-[#1f3320] disabled:text-[#4d7a4d] focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[#fbbf24]"
  {disabled}
  on:click={() => onRetry(row)}
>
  Retry
</button>
