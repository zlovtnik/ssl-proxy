/**
 * Engineer / Operator segmented control for the two audience cards.
 * Without JS both cards stack (toggle stays hidden). With JS the inactive
 * card is hidden + inert + aria-hidden so layout tests never see overlap.
 */
import { createSignal, For, onMount } from 'solid-js';
import { Check } from 'lucide-solid';
import { getProduct } from '../data/products';

const product = getProduct('octopus');
const labels = ['I am an Engineer', 'I am an Operator'] as const;

export default function OctopusAudienceToggle() {
  const [active, setActive] = createSignal(0);
  const [ready, setReady] = createSignal(false);
  const [entering, setEntering] = createSignal<number | null>(null);
  onMount(() => setReady(true));

  const select = (index: number) => {
    if (active() === index) return;
    setActive(index);
    setEntering(index);
    window.setTimeout(() => setEntering(null), 220);
  };

  return (
    <div
      class="audience-split"
      data-ux="audience-toggle"
      classList={{ 'is-toggled': ready() }}
    >
      <fieldset
        class="audience-toggle"
        aria-label="Choose audience view"
        hidden={!ready()}
      >
        <For each={labels}>
          {(label, index) => (
            <button
              type="button"
              aria-pressed={active() === index()}
              onClick={() => select(index())}
            >
              {label}
            </button>
          )}
        </For>
      </fieldset>
      <div class="audience-grid">
        <For each={product.audiences}>
          {(audience, index) => {
            const inactive = () => ready() && active() !== index();
            return (
              <article
                class="audience-card"
                hidden={inactive()}
                inert={inactive()}
                aria-hidden={inactive()}
                data-entering={
                  ready() && entering() === index() ? 'true' : undefined
                }
              >
                <p class="eyebrow">{audience.title.toUpperCase()}</p>
                <h3>{audience.proposition}</h3>
                <ul class="checklist">
                  <For each={audience.points}>
                    {(point) => (
                      <li>
                        <Check size={18} aria-hidden="true" />
                        <span>{point}</span>
                      </li>
                    )}
                  </For>
                </ul>
              </article>
            );
          }}
        </For>
      </div>
    </div>
  );
}
