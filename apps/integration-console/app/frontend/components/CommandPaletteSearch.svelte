<script>
  let { fields = [], onSearch = () => {}, onFetchValues = null } = $props()

  const safeFields = $derived(fields.filter(f => !f.internal && !f.hidden))

  let activeQuery = $state({ field: null, operator: null, value: '' })
  let step = $state('field') // 'field' | 'operator' | 'value'
  let isOpen = $state(false)
  let searchInput = $state('')
  let inputRef = $state(null)
  let valueCache = $state(new Map()) // Map<fieldKey, { values: [], timestamp: number }>
  let loadingValues = $state(false)
  let availableValues = $state([])

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

  const filteredValues = $derived(
    searchInput.trim() === ''
      ? availableValues
      : availableValues.filter(v => String(v).toLowerCase().includes(searchInput.toLowerCase()))
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

  async function selectOperator(operator) {
    activeQuery.operator = operator.key
    step = 'value'
    searchInput = ''
    
    if (activeQuery.field?.type === 'select') {
      await loadDistinctValues()
      isOpen = true
    } else {
      isOpen = false
    }
  }

  async function loadDistinctValues() {
    if (!activeQuery.field || !onFetchValues) {
      availableValues = []
      return
    }

    const fieldKey = activeQuery.field.key
    const cached = valueCache.get(fieldKey)
    const now = Date.now()
    
    // Check if cache is valid (less than 60 seconds old)
    if (cached && (now - cached.timestamp) < 60000) {
      availableValues = cached.values
      return
    }

    // Fetch new values
    loadingValues = true
    try {
      const values = await onFetchValues(fieldKey)
      valueCache.set(fieldKey, { values, timestamp: now })
      availableValues = values
    } catch (err) {
      console.error('Failed to load distinct values:', err)
      availableValues = []
    } finally {
      loadingValues = false
    }
  }

  function selectValue(value) {
    activeQuery.value = value
    isOpen = false
  }

  function isEmptyValue(value) {
    return value === null || value === undefined || value === ''
  }

  function commitSearch() {
    if (activeQuery.field && activeQuery.operator && !isEmptyValue(activeQuery.value)) {
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
        <button onclick={reset}>x</button>
      </span>
    {/if}

    {#if activeQuery.operator}
      <span class="pill operator-pill">
        {availableOperators.find(op => op.key === activeQuery.operator)?.label || activeQuery.operator}
      </span>
    {/if}

    {#if step === 'value'}
      {#if activeQuery.field?.type === 'select'}
        <input
          type="text"
          bind:value={searchInput}
          placeholder={loadingValues ? 'Loading...' : 'Search values...'}
          onfocus={() => isOpen = true}
          onkeydown={handleKeydown}
          class="value-input"
          disabled={loadingValues}
        />
      {:else}
        <input
          type={activeQuery.field?.type === 'number' ? 'number' : activeQuery.field?.type === 'date' ? 'date' : 'text'}
          bind:value={activeQuery.value}
          placeholder="Enter value..."
          onkeydown={handleKeydown}
          class="value-input"
        />
      {/if}
      <button onclick={commitSearch} class="commit-btn" disabled={isEmptyValue(activeQuery.value)}>Search</button>
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

  {#if isOpen}
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
      {:else if step === 'value' && activeQuery.field?.type === 'select'}
        {#if loadingValues}
          <div class="dropdown-item loading">Loading values...</div>
        {:else if filteredValues.length === 0}
          <div class="dropdown-item empty">No values found</div>
        {:else}
          {#each filteredValues as value}
            <button class="dropdown-item" onclick={() => selectValue(value)}>
              {value}
            </button>
          {/each}
        {/if}
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
    background: var(--color-filter-chip);
    color: var(--color-accent-vivid);
    border: 1px solid var(--color-border-strong);
  }

  .operator-pill {
    background: var(--color-filter-chip-muted);
    color: var(--color-text-muted);
    border: 1px solid var(--color-border-muted);
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
    background: var(--color-accent);
    color: var(--color-on-accent);
    border: 1px solid var(--color-accent);
    border-radius: 4px;
    font-size: 0.875rem;
    cursor: pointer;
    font-weight: 500;
  }

  .commit-btn:hover:not(:disabled) {
    background: var(--color-accent-vivid);
  }

  .commit-btn:disabled {
    background: var(--color-bg);
    color: var(--color-text-faint);
    border-color: var(--color-border-muted);
    cursor: not-allowed;
    opacity: 0.6;
  }

  .value-input:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .dropdown {
    position: absolute;
    top: calc(100% + 4px);
    background: var(--color-bg, white);
    border: 1px solid var(--color-control-border, #ddd);
    border-radius: 6px;
    box-shadow: var(--shadow-popover);
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

  .dropdown-item:hover:not(.loading):not(.empty) {
    background: var(--color-accent-surface);
  }

  .dropdown-item.loading,
  .dropdown-item.empty {
    cursor: default;
    color: var(--color-text-faint, #999);
    font-style: italic;
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
