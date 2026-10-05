import { createSignal, For, onMount } from 'solid-js';
import { investigations } from '../data/fixtures';
import { products } from '../data/products';

export default function SearchDemo() {
  const [selected, setSelected] = createSignal(0);
  const [ready, setReady] = createSignal(false);
  onMount(() => setReady(true));
  const sample = () => investigations[selected()];
  return (
    <div class="demo-panel search-demo">
      <div class="demo-top">
        <h2>Atheros Search / investigation</h2>
        <span class="sample-label">Synthetic data</span>
      </div>
      <div class="demo-content">
        <label for="sample-query">1. Choose a sample query</label>
        <select
          id="sample-query"
          disabled={!ready()}
          value={selected()}
          onChange={(event) => setSelected(Number(event.currentTarget.value))}
        >
          <For each={investigations}>
            {(item, index) => <option value={index()}>{item.query}</option>}
          </For>
        </select>
        <button
          type="button"
          disabled={!ready()}
          onClick={() => setSelected((selected() + 1) % investigations.length)}
        >
          Try the next sample query
        </button>
        <div aria-live="polite" aria-atomic="true" class="result">
          <p class="eyebrow">2. Inspect the matching record</p>
          <h3>{sample().record}</h3>
          <p>{sample().source} / sample hybrid result</p>
        </div>
        <details>
          <summary>3. Open the ranking explanation</summary>
          <p>{sample().explanation}</p>
          <p>No measured relevance score is implied by this example.</p>
        </details>
        <details>
          <summary>4. Inspect observed relationships</summary>
          <p>{sample().relation}</p>
          <p class="caveat">{products[0].caveat}</p>
        </details>
      </div>
    </div>
  );
}
