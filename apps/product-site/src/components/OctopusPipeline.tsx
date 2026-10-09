/**
 * Pipeline stage selector with emphasis-all-visible mode.
 * All three workflow steps stay in the DOM; the packet track is decorative.
 */
import { createSignal, For, onMount } from 'solid-js';
import { getProduct } from '../data/products';

type WorkflowItem = {
  step: string;
  stageLabel?: string;
  input: string;
  processing: string;
  output: string;
};

const product = getProduct('octopus');
const steps = product.workflow as readonly WorkflowItem[];

export default function OctopusPipeline() {
  const [active, setActive] = createSignal(0);
  const [ready, setReady] = createSignal(false);
  onMount(() => setReady(true));

  return (
    <div class="octopus-pipeline" data-ux="pipeline">
      <fieldset
        class="pipeline-selector"
        aria-label="Pipeline stage emphasis"
        hidden={!ready()}
      >
        <For each={steps}>
          {(item, index) => (
            <button
              type="button"
              disabled={!ready()}
              aria-pressed={active() === index()}
              onClick={() => setActive(index())}
            >
              {item.stageLabel ?? item.step}
            </button>
          )}
        </For>
      </fieldset>
      <div class="pipeline-track" aria-hidden="true">
        <span class="pipeline-packet" data-step={active()} />
      </div>
      <ol class="workflow-steps">
        <For each={steps}>
          {(item, index) => (
            <li
              class="workflow-step"
              data-emphasis={ready() ? String(active() === index()) : undefined}
            >
              <span class="workflow-index">
                <span>
                  0{index() + 1} / {item.step}
                </span>
                {item.stageLabel ? (
                  <span class="stage-chip">{item.stageLabel}</span>
                ) : null}
              </span>
              <h3>{item.step}</h3>
              <dl>
                <dt>Input</dt>
                <dd>{item.input}</dd>
                <dt>Processing</dt>
                <dd>{item.processing}</dd>
                <dt>Output</dt>
                <dd>{item.output}</dd>
              </dl>
            </li>
          )}
        </For>
      </ol>
    </div>
  );
}
