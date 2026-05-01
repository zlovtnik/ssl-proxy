<script>
  let { fields = [], onSearch = () => {} } = $props()

  const safeFields = $derived(fields.filter(f => !f.internal && !f.hidden))

  let activeQuery = $state({ field: null, operator: null, value: '' })
  let step = $state('field') // 'field' | 'operator' | 'value'
  let isOpen = $state(false)
  let searchInput = $state('')
  let inputRef = $state(null)

  const defaultOperators = {
    text: [
      { key: "contains", label: "contains" },
      { key: "equals", label: "equals" },
      { key: "starts_with", label: "starts with" }
    ],
    select: [
      { key: "equals", label: "equals" },
      { key: "not_equals", label: "does not equal" }
    ],
    number: [
      { key: "equals", label: "=" },
      { key: "greater_than", label: ">" },
      { key: "less_than", label: "<" }
    ],
    boolean: [{ key: "equals", label: "is" }],
    date: [
      { key: "equals", label: "on" },
      { key: "after", label: "after" },
      { key: "before", label: "before" }
    ]
  }

  const filteredFields = $derived(
    searchInput.trim() === ''
      ? safeFields
      : safeFields.filter(f => f.label.toLowerCase().includes(searchInput.toLowerCase()))
  )

  const availableOperators = $derived(
    activeQuery.field 
      ? (activeQuery.field.operators || defaultOperators[activeQuery.field.type] || defaultOperators.text)
      : []
  )

  function selectField(field) {
    activeQuery.field = field
    step = 'operator'
    searchInput = ''
  }

  function selectOperator(operator) {
    activeQuery.operator = operator.key
    step = 'value'
    isOpen = false
  }

  function commitSearch() {
    if (activeQuery.field && activeQuery.operator && activeQuery.value) {
      onSearch({ ...activeQuery })
      reset()
    }
  }

  function reset() {
    activeQuery = { field: null, operator: null, value: '' }
    step = 'field'
    searchInput = ''
  }

  function handleKeydown(e) {
    if (e.key === 'Enter') {
      if (step === 'value') commitSearch()
    } else if (e.key === 'Escape') {
      reset()
      isOpen = false
    }
  }
</script>

<div class="command-palette">
  <div class="input-wrapper">
    {#if activeQuery.field}
      <span class="pill field-pill">
        {activeQuery.field.label}
        <button onclick={reset}>×</button>
      </span>
    {/if}

    {#if activeQuery.operator}
      <span class="pill operator-pill">
        {availableOperators.find(op => op.key === activeQuery.operator)?.label || activeQuery.operator}
      </span>
    {/if}

    {#if step === 'value'}
      <input
        type={activeQuery.field?.type === 'number' ? 'number' : activeQuery.field?.type === 'date' ? 'date' : 'text'}
        bind:value={activeQuery.value}
        placeholder="Enter value..."
        onkeydown={handleKeydown}
        class="value-input"
      />
      <button onclick={commitSearch} class="commit-btn">Search</button>
    {:else}
      <input
        bind:this={inputRef}
        type="text"
        bind:value={searchInput}
        placeholder={step === 'field' ? 'Search fields...' : 'Select operator...'}
        onfocus={() => isOpen = true}
        onkeydown={handleKeydown}
        class="search-input"
      />
    {/if}
  </div>

  {#if isOpen && step !== 'value'}
    <div class="dropdown" style="left: {activeQuery.field ? inputRef?.offsetLeft || 0 : 0}px;">
      {#if step === 'field'}
        {#each filteredFields as field}
          <button class="dropdown-item" onclick={() => selectField(field)}>
            <span class="item-label">{field.label}</span>
            <span class="item-type">{field.type}</span>
          </button>
        {/each}
      {:else if step === 'operator'}
        {#each availableOperators as operator}
          <button class="dropdown-item" onclick={() => selectOperator(operator)}>
            {operator.label}
          </button>
        {/each}
      {/if}
    </div>
  {/if}
</div>

<style>
  .command-palette {
    position: relative;
    width: 100%;
  }

  .input-wrapper {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    border: 1px solid var(--color-control-border, #ccc);
    border-radius: 6px;
    background: var(--color-bg, white);
    min-height: 42px;
  }

  .pill {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 10px;
    border-radius: 4px;
    font-size: 0.875rem;
    font-weight: 500;
  }

  .field-pill {
    background: #007bff;
    color: white;
  }

  .operator-pill {
    background: #6c757d;
    color: white;
  }

  .pill button {
    background: none;
    border: none;
    color: inherit;
    font-size: 1.2rem;
    line-height: 1;
    cursor: pointer;
    padding: 0;
    margin: 0;
  }

  .search-input,
  .value-input {
    flex: 1;
    border: none;
    outline: none;
    background: transparent;
    font-size: 0.875rem;
    color: var(--color-text, #000);
  }

  .commit-btn {
    padding: 4px 12px;
    background: #28a745;
    color: white;
    border: none;
    border-radius: 4px;
    font-size: 0.875rem;
    cursor: pointer;
    font-weight: 500;
  }

  .commit-btn:hover {
    background: #218838;
  }

  .dropdown {
    position: absolute;
    top: calc(100% + 4px);
    background: var(--color-bg, white);
    border: 1px solid var(--color-control-border, #ddd);
    border-radius: 6px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
    max-height: 300px;
    overflow-y: auto;
    z-index: 100;
    min-width: 200px;
    width: max-content;
    max-width: 400px;
  }

  .dropdown-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    padding: 10px 12px;
    border: none;
    background: none;
    text-align: left;
    cursor: pointer;
    font-size: 0.875rem;
    color: var(--color-text, #000);
  }

  .dropdown-item:hover {
    background: var(--color-bg-hover, #f0f0f0);
  }

  .item-label {
    font-weight: 500;
  }

  .item-type {
    font-size: 0.75rem;
    color: var(--color-text-faint, #999);
    text-transform: uppercase;
  }
</style>
