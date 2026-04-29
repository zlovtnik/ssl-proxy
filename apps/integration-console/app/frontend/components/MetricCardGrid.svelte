<script>
  import MetricCard from "./MetricCard.svelte"

  export let cards = []
  export let columns = 3

  $: gridClass = {
    2: "md:grid-cols-2",
    3: "md:grid-cols-2 lg:grid-cols-3",
    4: "md:grid-cols-2 lg:grid-cols-4"
  }[columns] || "md:grid-cols-2 lg:grid-cols-3"
</script>

<section class={`grid grid-cols-1 gap-4 ${gridClass}`}>
  {#each cards as card}
    <MetricCard {...card} />
  {/each}
</section>

