import {
  createMemo,
  createSignal,
  For,
  Show,
  onMount,
  onCleanup,
} from 'solid-js';
import { investigations, migrationSteps } from '../data/fixtures';

export default function LandingPlayground() {
  const [product, setProduct] = createSignal('search');
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
      setProduct(value === 'migrator' ? 'migrator' : 'search');
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
      `${item.record} ${item.source} ${item.query}`
        .toLowerCase()
        .includes(query().trim().toLowerCase()),
    ),
  );
  const record = () => investigations[selected()];
  return (
    <div
      id="playground"
      class="landing-playground"
      classList={{ 'preview-migrator': product() === 'migrator' }}
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
        <button
          data-product="search"
          disabled={!ready()}
          aria-pressed={product() === 'search'}
          onClick={() => setProduct('search')}
        >
          Atheros Search
        </button>
        <button
          data-product="migrator"
          disabled={!ready()}
          aria-pressed={product() === 'migrator'}
          onClick={() => setProduct('migrator')}
        >
          Schema Migrator
        </button>
      </div>
      <div class="preview-panels">
        <div
          class="preview-body preview-panel panel-migrator"
          classList={{ 'is-inactive': product() !== 'migrator' }}
          inert={product() !== 'migrator'}
          aria-hidden={product() !== 'migrator'}
        >
          <div class="preview-title">
            <h2>Review before the run.</h2>
            <span class="preview-badge">OFFLINE</span>
          </div>
          <div
            class="preview-steps"
            role="group"
            aria-label="Sample migration steps"
          >
            <For each={migrationSteps}>
              {(item, index) => (
                <button
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
          <div class="preview-file">
            <span>{migrationSteps[step()].title}</span>
            <span>SQL / SAMPLE</span>
          </div>
          <pre class="preview-code">{migrationSteps[step()].code}</pre>
          <p class="preview-explanation">{migrationSteps[step()].text}</p>
          <p class="preview-caveat">
            SQL-file snapshots preserve source files and checksums. They do not
            back up database data.
          </p>
          <a class="text-link preview-full" href="/schema-migrator/#demo">
            Open the migration walkthrough{' '}
            <span aria-hidden="true">&#8594;</span>
          </a>
        </div>
        <div
          class="preview-body preview-panel panel-search"
          classList={{ 'is-inactive': product() !== 'search' }}
          inert={product() !== 'search'}
          aria-hidden={product() !== 'search'}
        >
          <div class="preview-title">
            <h2>Follow the evidence.</h2>
            <span class="preview-badge">SYNTHETIC</span>
          </div>
          <label class="preview-search">
            <svg
              viewBox="0 0 24 24"
              width="20"
              height="20"
              fill="none"
              stroke="currentColor"
              stroke-width="1.5"
              aria-hidden="true"
            >
              <circle cx="10" cy="10" r="6" />
              <path d="m15 15 5 5" />
            </svg>
            <input
              aria-label="Filter sample observations"
              placeholder="Search guest, proxy, or wireless..."
              value={query()}
              onInput={(event) => setQuery(event.currentTarget.value)}
              disabled={!ready()}
            />
          </label>
          <div class="preview-table-heading">
            <span>OBSERVATION</span>
            <span>INSPECT</span>
          </div>
          <div class="preview-records">
            <For each={results()}>
              {(item) => (
                <button
                  class="preview-record"
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
                  <svg
                    viewBox="0 0 24 24"
                    width="26"
                    height="26"
                    fill="none"
                    stroke="currentColor"
                    stroke-width="1.4"
                    aria-hidden="true"
                  >
                    <path d="m12 2 10 10-10 10L2 12Z" />
                    <path d="m12 7 5 5-5 5-5-5Z" />
                  </svg>
                  <span>
                    <strong>{item.record}</strong>
                    <small>{item.source}</small>
                  </span>
                  <span aria-hidden="true">&#8599;</span>
                </button>
              )}
            </For>
            <Show when={!results().length}>
              <p class="preview-empty">
                No sample observations match. Try "guest" or "proxy".
              </p>
            </Show>
          </div>
          <p class="preview-count" role="status">
            {results().length} sample observations / local filtering
          </p>
          <Show when={results().includes(record())}>
            <div class="preview-evidence">
              <p class="eyebrow">
                RECORD CONTEXT / {selected() === 0 ? 'WIRELESS' : 'PROXY'}
              </p>
              <div class="evidence-path" aria-hidden="true">
                <span>{record().record}</span>
                <svg viewBox="0 0 90 24" fill="none" stroke="currentColor">
                  <path d="M0 12h90" stroke-dasharray="3 4" />
                  <circle cx="45" cy="12" r="4" fill="currentColor" />
                </svg>
                <span>
                  {selected() === 0
                    ? 'Lobby access point'
                    : 'Device identifier 03'}
                </span>
              </div>
              <p>{record().relation}</p>
              <p class="preview-caveat">
                An observation does not confirm a current connection or device
                identity.
              </p>
            </div>
          </Show>
          <a class="text-link preview-full" href="/atheros-search/#demo">
            Open the full investigation <span aria-hidden="true">&#8594;</span>
          </a>
        </div>
      </div>
      <div class="preview-caption">
        <span class="status-dot" aria-hidden="true" />
        Explore freely. No account. No production connection.
      </div>
      <noscript>
        <p class="preview-explanation">
          Interactive controls need JavaScript. Follow either product link to
          read its sample workflow.
        </p>
      </noscript>
    </div>
  );
}
