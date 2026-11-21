// Layout rules found in the browser check (1.49.3): stylesheet checks in the
// style of the render tests, for config.css (shared by all Enterprise tabs)
// and the Enterprise block of topology.css.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const configCss = readFileSync(join(here, 'config.css'), 'utf8');
const topoCss = readFileSync(join(here, '../../topology.css'), 'utf8');

test('router and version rows become cards until their columns fit (no cut-off buttons at 768 / 1024 px)', () => {
  const bp = Number(/@container cfgrows \(max-width: (\d+)px\)/.exec(configCss)[1]);
  // narrowest the table rows fit in: sum of minmax floors + fixed tracks + gaps + padding
  for (const sel of ['cfg-rrow', 'cfg-vrow']) {
    const cols = new RegExp(`\\.${sel} \\{[^}]*grid-template-columns: ([^;]+);`).exec(configCss)[1];
    const tracks = cols.match(/minmax\((\d+)px|(?<![(\d])(\d+)px/g).map(t => Number(/(\d+)/.exec(t)[1]));
    const need = tracks.reduce((a, b) => a + b, 0) + (tracks.length - 1) * 8 + 20;
    assert.ok(bp >= need, `${sel}: needs ${need} px, cards below ${bp} px`);
  }
});

test('labels inside the Enterprise tabs are readable (muted text at least 45 % white)', () => {
  const m = /\.cfg \{ --text-muted: rgba\(255, 255, 255, (0\.\d+)\); \}/.exec(configCss);
  assert.ok(m, 'override present');
  assert.ok(Number(m[1]) >= 0.45);
});

test('the always-dark panel asks for dark native controls', () => {
  assert.match(topoCss, /\.topo-app \{[^}]*color-scheme: dark;/);
});

test('Enterprise sub-tabs are 40 px touch targets on phones', () => {
  assert.match(topoCss, /@media \(max-width: 600px\) \{\s*\/\*[^*]*\*\/\s*\.ent-tab \{ min-height: 40px; \}/);
});
