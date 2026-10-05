import { createSignal, For, onMount } from 'solid-js';
import { migrationSteps } from '../data/fixtures';
import { products } from '../data/products';

export default function MigratorDemo() {
  const [step, setStep] = createSignal(0);
  const [ready, setReady] = createSignal(false);
  onMount(() => setReady(true));
  const current = () => migrationSteps[step()];
  return (
    <div class="demo-panel migrator-demo">
      <div class="demo-top">
        <h2>Schema Migrator / change review</h2>
        <span class="sample-label">Synthetic data</span>
      </div>
      <div class="demo-content">
        <div
          class="step-controls"
          role="group"
          aria-label="Migration review steps"
        >
          <For each={migrationSteps}>
            {(item, index) => (
              <button
                type="button"
                disabled={!ready()}
                aria-pressed={step() === index()}
                onClick={() => setStep(index())}
              >
                {index() + 1}. {item.name}
              </button>
            )}
          </For>
        </div>
        <section aria-live="polite" aria-atomic="true" class="run-stage">
          <h3>{current().title}</h3>
          <p>{current().text}</p>
          <pre>
            <code>{current().code}</code>
          </pre>
        </section>
        <p class="caveat">{products[1].caveat}</p>
        <p class="fine-print">
          SQL means Structured Query Language. This demo never connects to or
          changes a database.
        </p>
        <details>
          <summary>Read all steps as text</summary>
          <For each={migrationSteps}>
            {(item) => (
              <section>
                <h4>{item.title}</h4>
                <p>{item.text}</p>
                <pre>
                  <code>{item.code}</code>
                </pre>
              </section>
            )}
          </For>
        </details>
      </div>
    </div>
  );
}
