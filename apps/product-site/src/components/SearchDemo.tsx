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
        <h2>Atheros Search / illustrative site review</h2>
        <span class="sample-label">Synthetic sample</span>
      </div>
      <p class="fine-print">
        This sample illustrates a site-to-indicator-to-observation path. The
        current production console does not show this complete site overview end
        to end.
      </p>
      <div class="demo-content">
        <label for="sample-site">1. Choose a monitored sample site</label>
        <select
          id="sample-site"
          data-analytics-product="atheros_search"
          data-analytics-action="sample_site"
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
          data-analytics-product="atheros_search"
          data-analytics-action="next_sample_site"
          disabled={!ready()}
          onClick={() => setSelected((selected() + 1) % investigations.length)}
        >
          Try the next sample site
        </button>
        <div aria-live="polite" aria-atomic="true" class="result">
          <p class="eyebrow">2. Review an indicator for analyst review</p>
          <h3>{sample().indicator}</h3>
          <p>
            {sample().site} / {sample().sensor}
          </p>
          <p>{sample().reason}</p>
        </div>
        <details>
          <summary>3. Review why the indicator was raised</summary>
          <p>{sample().explanation}</p>
        </details>
        <details>
          <summary>4. Inspect the supporting observation</summary>
          <p>
            {sample().record} / {sample().source}
          </p>
          <p>{sample().channel}</p>
          <p>{sample().relation}</p>
          <p class="caveat">{products[0].caveat}</p>
        </details>
      </div>
    </div>
  );
}
