// Tests of the traffic values on the topology (node:test). The adapter of
// the snapshot (api.ts) is bundled once with esbuild, as in the render
// tests. Invented values only; no real router, no real Home Assistant.
import { test, before } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { build } from 'esbuild';
import { parseRouterTraffic, parseUplinkTraffic, routerTrafficRows, uplinkTrafficRows } from './trafficTopology.ts';

const here = dirname(fileURLToPath(import.meta.url));
const root = join(here, '../../..');
const outFile = join(root, 'node_modules/.cache/traffic-topology-test/bundle.mjs');

let A;
before(async () => {
  mkdirSync(dirname(outFile), { recursive: true });
  await build({
    stdin: { contents: "export { adaptSnapshot } from '../../api';", resolveDir: here, loader: 'ts' },
    bundle: true, format: 'esm', platform: 'node', outfile: outFile, logLevel: 'silent',
    external: ['react', 'react-dom'], define: { 'import.meta.env.DEV': 'false' },
  });
  A = await import(pathToFileURL(outFile).href);
});

const GW = '02:00:5e:20:00:01';
const AP = '02:00:5e:20:00:02';
const port = (over = {}) => ({ rx_bps: 2_000_000, tx_bps: 9_000_000, down_bps: null, up_bps: null, coverage: 'partial', link_mbps: 1000, utilization_pct: 0.9, utilization_reason: null, ...over });

function snapshot(withTraffic) {
  const gwTraffic = { state: 'available', reason: null, wan_points: 1, wan: { rx_bps: 8e7, tx_bps: 9e6, down_bps: 8e7, up_bps: 9e6, coverage: 'partial' }, ports: { lan1: port() } };
  return {
    generated_at: '2026-11-21T10:00:00Z',
    nodes: [
      { id: GW, type: 'router', label: 'gw', role: 'gateway', attributes: { model: 'x', ...(withTraffic ? { traffic: gwTraffic } : {}) } },
      { id: AP, type: 'router', label: 'ap', role: 'ap', attributes: { model: 'y', ...(withTraffic ? { traffic: { state: 'unavailable', reason: 'router_not_measured' } } : {}) } },
    ],
    edges: [{
      id: `${GW}--uplink--${AP}`, from: GW, to: AP, relationship: 'router_uplink',
      attributes: { link_type: 'lan', from_port: 'lan1', to_port: 'wan', ...(withTraffic ? { traffic: { from_port: port(), from_port_reason: null, to_port: null, to_port_reason: 'router_not_measured' } } : {}) },
    }],
    clients: [],
    interfaces: [],
    meta: withTraffic ? { traffic: { status: 'ready', reasons: [], flow_relations: { state: 'unavailable', reason: 'needs_flow_source' } } } : {},
  };
}

test('off: no traffic key, no rows, and the adapted topology is unchanged', () => {
  assert.equal(parseRouterTraffic({ model: 'x' }), undefined);
  assert.equal(parseUplinkTraffic({ from_port: 'lan1' }), undefined);
  assert.deepEqual(routerTrafficRows(undefined), []);
  assert.deepEqual(uplinkTrafficRows(undefined), []);
  const off = A.adaptSnapshot(snapshot(false));
  assert.equal(off.gateway.traffic, undefined);
  assert.equal(off.accessPoints[0].traffic, undefined);
  assert.equal(off.accessPoints[0].uplinkTraffic, undefined);
  assert.doesNotMatch(JSON.stringify(off), /"(uplinkT|t)raffic"/);
});

test('on: only the traffic fields differ; everything else is as without it', () => {
  const on = A.adaptSnapshot(snapshot(true));
  assert.equal(on.gateway.traffic.state, 'available');
  assert.equal(on.accessPoints[0].traffic.state, 'unavailable');
  assert.equal(on.accessPoints[0].uplinkTraffic.toReason, 'router_not_measured');
  const strip = d => JSON.parse(JSON.stringify(d, (k, v) => (k === 'traffic' || k === 'uplinkTraffic' ? undefined : v)));
  const off = A.adaptSnapshot(snapshot(false));
  assert.deepEqual(strip({ ...on, timestamp: 0 }), strip({ ...off, timestamp: 0 }));
});

test('rows: download/upload where named, rx/tx otherwise; unknown is "—" with reason', () => {
  const t = parseRouterTraffic(snapshot(true).nodes[0].attributes);
  const rows = routerTrafficRows(t);
  assert.equal(rows[0].label, 'WAN');
  assert.match(rows[0].value, /80,0 Mbit\/s ↓ · 9,0 Mbit\/s ↑/);
  assert.match(rows[0].value, /Abdeckung teilweise/);
  assert.equal(rows[1].label, 'LAN1');
  assert.match(rows[1].value, /^rx 2,0 Mbit\/s · tx 9,0 Mbit\/s · 0,9 % Last$/);
  const ap = routerTrafficRows(parseRouterTraffic(snapshot(true).nodes[1].attributes));
  assert.deepEqual(ap, [{ label: 'Traffic', value: '— Router nicht erfasst' }]);
  const up = uplinkTrafficRows(parseUplinkTraffic(snapshot(true).edges[0].attributes));
  assert.match(up[0].value, /rx 2,0 Mbit\/s/);
  assert.equal(up[1].value, '— Router nicht erfasst');
  const noLink = routerTrafficRows({ state: 'available', reason: null, wan: null, wanPoints: 0, ports: { lan2: { ...parseUplinkTraffic({ traffic: { from_port: port({ utilization_pct: null, utilization_reason: 'link_speed_unknown', link_mbps: null }) } }).fromPort } } });
  assert.equal(noLink[0].value, '— kein WAN-Messpunkt');
  assert.match(noLink[1].value, /Last — Link-Geschwindigkeit unbekannt/);
  assert.doesNotMatch(JSON.stringify(rows), /: 0 |0 bit\/s/);
});

test('junk never throws', () => {
  for (const bad of [null, 1, 'x', [], { traffic: 'x' }, { traffic: { ports: { a: 1, b: null } } }]) {
    routerTrafficRows(parseRouterTraffic(bad));
    uplinkTrafficRows(parseUplinkTraffic(bad));
  }
});
