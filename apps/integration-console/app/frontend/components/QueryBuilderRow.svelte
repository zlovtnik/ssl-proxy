<script>
  let { filter = {}, fields = [], removable = false, onChange = () => {}, onRemove = () => {} } = $props()

  const defaultOperators = {
    text: [
      { key: "contains", label: "contains" },
      { key: "equals", label: "equals" },
      { key: "starts_with", label: "starts with" },
      { key: "is_empty", label: "is empty" },
      { key: "is_not_empty", label: "is not empty" }
    ],
    select: [
      { key: "equals", label: "equals" },
      { key: "not_equals", label: "does not equal" },
      { key: "is_empty", label: "is empty" },
      { key: "is_not_empty", label: "is not empty" }
    ],
    number: [
      { key: "equals", label: "=" },
      { key: "greater_than", label: ">" },
      { key: "less_than", label: "<" },
      { key: "between", label: "between" },
      { key: "is_empty", label: "is empty" }
    ],
    boolean: [
      { key: "equals", label: "is" }
    ],
    date: [
      { key: "equals", label: "on" },
      { key: "after", label: "after" },
      { key: "before", label: "before" },
      { key: "between", label: "between" },
      { key: "is_empty", label: "is empty" }
    ]
  }

  const selectedField = $derived(fields.find((field) => field.key === filter.field) || fields[0] || {})
  const operators = $derived(normalizeOperators(selectedField.operators || defaultOperators[selectedField.type] || defaultOperators.text))
  const selectedOperator = $derived(operators.find((operator) => operator.key === filter.operator) || operators[0] || {})
  const valueHidden = $derived(["is_empty", "is_not_empty"].includes(selectedOperator.key))

  function normalizeOperators(operators) {
    return operators.map((operator) => typeof operator === "string" ? { key: operator, label: operator } : operator)
  }

  function patch(changes) {
    const next = { ...filter, ...changes }
    if (changes.field) {
      const field = fields.find((item) => item.key === changes.field) || fields[0] || {}
      const nextOperators = normalizeOperators(field.operators || defaultOperators[field.type] || defaultOperators.text)
      next.operator = nextOperators[0]?.key || ""
      next.value = ""
    }
    if (["is_empty", "is_not_empty"].includes(next.operator)) next.value = ""
    onChange(next)
  }
</script>

<div class="query-builder-row grid gap-2 sm:grid-cols-[minmax(10rem,1fr)_minmax(9rem,0.75fr)_minmax(12rem,1.25fr)_2.25rem]">
  <label class="sr-only" for={`query-field-${filter.id}`}>Field</label>
  <select
    id={`query-field-${filter.id}`}
    class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-bg) px-3 py-2 text-sm text-(--color-text) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
    value={filter.field}
    aria-label="Filter field"
    onchange={(event) => patch({ field: event.currentTarget.value })}
  >
    {#each fields as field}
      <option value={field.key}>{field.label}</option>
    {/each}
  </select>

  <label class="sr-only" for={`query-operator-${filter.id}`}>Operator</label>
  <select
    id={`query-operator-${filter.id}`}
    class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-bg) px-3 py-2 text-sm text-(--color-text) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
    value={filter.operator}
    aria-label="Filter operator"
    onchange={(event) => patch({ operator: event.currentTarget.value })}
  >
    {#each operators as operator}
      <option value={operator.key}>{operator.label}</option>
    {/each}
  </select>

  {#if valueHidden}
    <div class="min-h-9 rounded-md border border-dashed border-(--color-border-muted) px-3 py-2 text-sm text-(--color-text-faint)">No value</div>
  {:else if selectedField.type === "select"}
    <label class="sr-only" for={`query-value-${filter.id}`}>Value</label>
    <select
      id={`query-value-${filter.id}`}
      class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-bg) px-3 py-2 text-sm text-(--color-text) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
      value={filter.value}
      aria-label="Filter value"
      onchange={(event) => patch({ value: event.currentTarget.value })}
    >
      <option value="">Any</option>
      {#each selectedField.options || [] as option}
        <option value={option.value ?? option.key}>{option.label}</option>
      {/each}
    </select>
  {:else if selectedField.type === "boolean"}
    <label class="sr-only" for={`query-value-${filter.id}`}>Value</label>
    <select
      id={`query-value-${filter.id}`}
      class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-bg) px-3 py-2 text-sm text-(--color-text) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
      value={filter.value}
      aria-label="Filter value"
      onchange={(event) => patch({ value: event.currentTarget.value })}
    >
      <option value="">Any</option>
      <option value="true">True</option>
      <option value="false">False</option>
    </select>
  {:else}
    <label class="sr-only" for={`query-value-${filter.id}`}>Value</label>
    <input
      id={`query-value-${filter.id}`}
      class="min-h-9 rounded-md border border-(--color-control-border) bg-(--color-bg) px-3 py-2 text-sm text-(--color-text) placeholder:text-(--color-text-faint) focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
      type={selectedField.type === "number" ? "number" : selectedField.type === "date" ? "date" : "text"}
      value={filter.value}
      aria-label="Filter value"
      placeholder="Value"
      oninput={(event) => patch({ value: event.currentTarget.value })}
    />
  {/if}

  <button
    type="button"
    class="min-h-9 rounded-md border border-(--color-border-muted) px-2 text-lg font-semibold text-(--color-danger-text) disabled:hidden focus-visible:outline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-(--color-focus)"
    aria-label="Remove filter"
    disabled={!removable}
    onclick={onRemove}
  >
    &times;
  </button>
</div>
