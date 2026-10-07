import {
  createMemo,
  createSignal,
  For,
  Show,
  onMount,
  onCleanup,
} from 'solid-js';
import { investigations, migrationSteps } from '../data/fixtures';
import { getProduct, products, type ProductId } from '../data/products';
import VpnDemo from './VpnDemo';
import { ArrowRight, ArrowUpRight, Diamond, Search } from 'lucide-solid';

const search = getProduct('search');
const migrator = getProduct('migrator');

export default function LandingPlayground() {
  const [product, setProduct] = createSignal<ProductId>('search');
  const [query, setQuery] = createSignal('');
  const [selected, setSelected] = createSignal(0);
  const [step, setStep] = createSignal(0);
  const [ready, setReady] = createSignal(false);
  onMount(() => {
    setReady(true);
    const links =
      document.querySelectorAll<HTMLAnchorElement>('[data-preview]');
    const explore = (event: MouseEvent) => {
      if (event.ctrlKey || event.metaKey || event.shiftKey || event.altKey)
        return;
      event.preventDefault();
      const value = (event.currentTarget as HTMLAnchorElement).dataset.preview;
      const target = products.find((item) => item.id === value);
      if (!target) return;
      setProduct(target.id);
      document
        .querySelector<HTMLButtonElement>(
          `#playground button[data-product="${product()}"]`,
        )
        ?.focus({ preventScroll: true });
      document.getElementById('playground')?.scrollIntoView({ block: 'start' });
    };
    links.forEach((link) => link.addEventListener('click', explore));
    onCleanup(() =>
      links.forEach((link) => link.removeEventListener('click', explore)),
    );
  });
  const results = createMemo(() =>
    investigations.filter((item) =>
      `${item.site} ${item.indicator} ${item.record} ${item.identifier} ${item.query}`
        .toLowerCase()
        .includes(query().trim().toLowerCase()),
    ),
  );
  const record = () => investigations[selected()];
  return (
    <div
      id="playground"
      class="landing-playground"
    >
      <div class="playground-chrome">
        <span class="chrome-dots" aria-hidden="true">
          <i />
          <i />
          <i />
        </span>
        <span>rclabs / playground</span>
        <span class="preview-badge">
          <span class="status-dot" aria-hidden="true" /> INTERACTIVE
        </span>
      </div>
      <div
        class="preview-switch"
        role="group"
        aria-label="Choose a product preview"
      >
        <For each={products}>{(item) => (
          <button
            data-product={item.id}
            data-analytics-product="landing"
            data-analytics-action={`choose_${item.id}`}
            disabled={!ready()}
            aria-pressed={product() === item.id}
            onClick={() => setProduct(item.id)}
          >{item.name}</button>
        )}</For>
      </div>
      <div class="preview-panels">
        <div
          class="preview-body preview-panel panel-migrator"
          hidden={product() !== 'migrator'}
          inert={product() !== 'migrator'}
          aria-hidden={product() !== 'migrator'}
        >
          <div class="preview-title">
            <h2>Review before the run.</h2>
            <span class="preview-badge">OFFLINE</span>
          </div>
          <div class="preview-layout">
          <div
            class="preview-steps"
            role="group"
            aria-label="Sample migration steps"
          >
            <For each={migrationSteps}>
              {(item, index) => (
                <button
                  data-analytics-product="landing"
                  data-analytics-action="migration_step"
                  aria-label={item.name}
                  disabled={!ready()}
                  aria-pressed={step() === index()}
                  onClick={() => setStep(index())}
                >
                  <span>0{index() + 1}</span>
                  {item.name}
                </button>
              )}
            </For>
          </div>
          <div class="preview-detail">
          <div class="preview-file">
            <span>{migrationSteps[step()].title}</span>
            <span>SQL / SAMPLE</span>
          </div>
          <pre class="preview-code">{migrationSteps[step()].code}</pre>
          <p class="preview-explanation">{migrationSteps[step()].text}</p>
          <p class="preview-caveat">{migrator.caveat}</p>
          <a class="text-link preview-full" href={`${migrator.path}#demo`}>
            Open the migration walkthrough{' '}
            <ArrowRight size={18} aria-hidden="true" />
          </a>
          </div>
          </div>
        </div>
        <div
          class="preview-body preview-panel panel-search"
          hidden={product() !== 'search'}
          inert={product() !== 'search'}
          aria-hidden={product() !== 'search'}
        >
          <div class="preview-title">
            <h2>Review wireless indicators by site.</h2>
            <span class="preview-badge">SYNTHETIC</span>
          </div>
          <div class="preview-layout">
          <div class="preview-inputs">
          <label class="preview-search">
            <Search size={20} aria-hidden="true" />
            <input
              aria-label="Filter sample sites, indicators, and observations"
              placeholder="Filter by site, indicator, or identifier..."
              value={query()}
              onInput={(event) => setQuery(event.currentTarget.value)}
              disabled={!ready()}
            />
          </label>
          <div class="preview-table-heading">
            <span>SITE / INDICATOR</span>
            <span>REVIEW</span>
          </div>
          <div class="preview-records">
            <For each={results()}>
              {(item) => (
                <button
                  class="preview-record"
                  data-analytics-product="landing"
                  data-analytics-action="wireless_sample"
                  aria-pressed={
                    record().record === item.record ? 'true' : 'false'
                  }
                  disabled={!ready()}
                  onClick={() =>
                    setSelected(
                      investigations.findIndex(
                        (candidate) => candidate.record === item.record,
                      ),
                    )
                  }
                >
                  <Diamond size={26} strokeWidth={1.5} aria-hidden="true" />
                  <span>
                    <strong>{item.indicator}</strong>
                    <small>
                      {item.site} / {item.record}
                    </small>
                  </span>
                  <ArrowUpRight size={18} aria-hidden="true" />
                </button>
              )}
            </For>
            <Show when={!results().length}>
              <p class="preview-empty">
                No sample observations match. Try a site name or indicator.
              </p>
            </Show>
          </div>
          <p class="preview-count" role="status">
            {results().length} wireless samples / local filtering
          </p>
          </div>
          <div class="preview-detail">
          <Show when={results().includes(record())}>
            <div class="preview-evidence">
              <p class="eyebrow">SITE / INDICATOR / SUPPORTING OBSERVATION</p>
              <div class="evidence-path" aria-hidden="true">
                <span>{record().site}</span>
                <svg viewBox="0 0 90 24" fill="none" stroke="currentColor">
                  <path d="M0 12h90" stroke-dasharray="3 4" />
                  <circle cx="45" cy="12" r="4" fill="currentColor" />
                </svg>
                <span>{record().indicator}</span>
                <svg viewBox="0 0 90 24" fill="none" stroke="currentColor">
                  <path d="M0 12h90" stroke-dasharray="3 4" />
                  <circle cx="45" cy="12" r="4" fill="currentColor" />
                </svg>
                <span>{record().record}</span>
              </div>
              <p>
                {record().sensor} / {record().channel}
              </p>
              <p>{record().reason}</p>
              <p>{record().relation}</p>
              <p class="preview-caveat">{search.caveat}</p>
            </div>
          </Show>
          <a class="text-link preview-full" href={`${search.path}#demo`}>
            Open the Search sample workflow{' '}
            <ArrowRight size={18} aria-hidden="true" />
          </a>
          </div>
          </div>
        </div>
        <div class="preview-panel panel-vpn" hidden={product() !== 'vpn'} inert={product() !== 'vpn'} aria-hidden={product() !== 'vpn'}>
          <VpnDemo embedded />
          <a class="text-link preview-full vpn-full" href={`${getProduct('vpn').path}#demo`}>
            Open the traffic walkthrough <ArrowRight size={18} aria-hidden="true" />
          </a>
        </div>
      </div>
      <div class="preview-caption">
        <span class="status-dot" aria-hidden="true" />
        Explore freely. No account. No production connection.
      </div>
      <noscript>
        <p class="preview-explanation">
          Interactive controls need JavaScript. Follow a product link to
          read its sample workflow.
        </p>
      </noscript>
    </div>
  );
}
