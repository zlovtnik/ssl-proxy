import { createSignal, For, onMount } from 'solid-js';
import { trafficFlows } from '../data/fixtures';
import { getProduct } from '../data/products';

const product = getProduct('vpn');

export default function VpnDemo(props: { embedded?: boolean }) {
  const [selected, setSelected] = createSignal(0);
  const [ready, setReady] = createSignal(false);
  const flow = () => trafficFlows[selected()];
  onMount(() => setReady(true));
  return (
    <div class="vpn-demo" classList={{ 'demo-panel': !props.embedded }}>
      <div class="demo-top">
        <h2>RCLabs VPN / Proxy / traffic review</h2>
        <span class="sample-label">Synthetic data</span>
      </div>
      <div class="demo-content demo-workspace">
        <div class="demo-inputs">
          <p class="eyebrow">01 / CHOOSE A FLOW</p>
          <label for={props.embedded ? 'preview-flow' : 'sample-flow'}>Sample traffic flow</label>
          <select
            id={props.embedded ? 'preview-flow' : 'sample-flow'}
            value={selected()}
            disabled={!ready()}
            onChange={(event) => setSelected(Number(event.currentTarget.value))}
          >
            <For each={trafficFlows}>{(item, index) => <option value={index()}>{item.label}</option>}</For>
          </select>
          <ol class="traffic-path" aria-label="Illustrative traffic path">
            <li><span>01</span><div><strong>WireGuard peer</strong><small>Configured ingress</small></div></li>
            <li><span>02</span><div><strong>Transparent proxy</strong><small>Category and policy</small></div></li>
            <li><span>03</span><div><strong>Audit publishing</strong><small>Configured backend</small></div></li>
          </ol>
        </div>
        <div class="demo-output">
          <section class="flow-result" aria-live="polite" aria-atomic="true">
            <p class="eyebrow">02 / INSPECT THE DECISION</p>
            <h3>{flow().destination}</h3>
            <dl class="flow-facts">
              <div><dt>Traffic category</dt><dd><code>{flow().category}</code></dd></div>
              <div><dt>Sample decision</dt><dd>{flow().decision}</dd></div>
            </dl>
            <p>{flow().reason}</p>
          </section>
          <details>
            <summary>Inspect the sample audit record</summary>
            <pre><code>{`Flow: sample-flow-00${selected() + 1}\nIngress: WireGuard / synthetic peer\nDestination: ${flow().destination}\nCategory: ${flow().category}\nDecision: ${flow().decision}\nEvidence: illustrative audit event\nTraffic sent: none`}</code></pre>
          </details>
          <p class="caveat">{product.caveat}</p>
          <details>
            <summary>Read all traffic categories as text</summary>
            <For each={trafficFlows}>{(item) => (
              <section><h4>{item.label} / <code>{item.category}</code></h4><p>{item.reason}</p></section>
            )}</For>
          </details>
        </div>
      </div>
    </div>
  );
}
