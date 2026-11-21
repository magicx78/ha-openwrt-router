// Narrow layout of the "Zeitreise" tab: wrapping filter bar, cards below
// the width of a timeline row (container query, the Network Diagnostics
// history pattern), touch-size controls on phones (stylesheet and markup
// checks, node:test, no dependencies).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const css = readFileSync(join(here, 'timemachine.css'), 'utf8');
const tsx = readFileSync(join(here, 'TimeMachineView.tsx'), 'utf8');
const wifiCss = readFileSync(join(here, '../wifi/wifi.css'), 'utf8');

const rule = sel => {
  const m = new RegExp(`(?:^|\\n)${sel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} \\{([^}]*)\\}`).exec(css);
  assert.ok(m, `rule ${sel}`);
  return m[1];
};

test('the list is a size container', () => {
  assert.match(rule('.tm-list'), /container: tmlist \/ inline-size;/);
});

test('below the width a row needs, every mark is a wrapping card with the title on its own line', () => {
  const m = /@container tmlist \(max-width: (\d+)px\) \{([\s\S]*?)\n\}/.exec(css);
  assert.ok(m, 'container rule present');
  assert.ok(Number(m[1]) >= 700, `breakpoint ${m[1]} px below the row's width`);
  const body = m[2];
  assert.match(body, /\.tm-mark \{[^}]*display: flex;[^}]*flex-wrap: wrap;/);
  assert.match(body, /\.tm-mark__main \{[^}]*flex: 1 1 100%;/);
  // card order follows the markup: time, severity, group / title + params / router, source
  const order = ['tm-mark__time', 'tm-mark__sev', 'tm-mark__group', 'tm-mark__main', 'tm-mark__router', 'tm-mark__source'];
  const at = order.map(c => tsx.indexOf(`"${c}`) >= 0 ? tsx.indexOf(`"${c}`) : tsx.indexOf(`${c} `));
  assert.ok(at.every(i => i > 0), 'all parts in the markup');
  assert.deepEqual([...at].sort((a, b) => a - b), at);
  assert.ok(tsx.indexOf('tm-mark__title') < tsx.indexOf('tm-mark__params'));
});

test('nothing forces a sideways scroll', () => {
  assert.match(rule('.tm'), /min-width: 0;/);
  assert.match(rule('.tm'), /overflow-wrap: anywhere;/);
  assert.match(rule('.tm-mark > *'), /min-width: 0;/);
  assert.match(rule('.tm-mark'), /minmax\(0, 1fr\)/);
  for (const sel of ['.tm-filter', '.tm-chips', '.tm-sources', '.tm-more']) assert.match(rule(sel), /flex-wrap: wrap;/, sel);
  assert.doesNotMatch(css, /overflow-x:\s*(auto|scroll)/);
  assert.doesNotMatch(css, /white-space: nowrap/);
  assert.match(rule('.tm-chip'), /white-space: normal;/);
  // sum of the fixed columns stays under the breakpoint (12.5px font)
  const cols = /grid-template-columns: ([^;]+);/.exec(rule('.tm-mark'))[1];
  const em = [...cols.matchAll(/([\d.]+)em/g)].reduce((s, x) => s + Number(x[1]), 0);
  assert.ok(em * 12.5 + 5 * 12 + 20 < 720 - 120, `fixed columns ${em}em leave room for the title`);
});

test('on phones, chips, select and buttons are as tall as in the other tabs (40 px)', () => {
  assert.match(wifiCss, /@media \(max-width: 600px\)[\s\S]*?\.wifi-nav__btn \{[^}]*min-height: 40px;/);
  const m = /@media \(max-width: 600px\) \{([\s\S]*?)\n\}/.exec(css);
  assert.ok(m);
  for (const sel of ['.tm-chip', '.tm-field select', '.tm-more .cfg-btn']) {
    assert.match(m[1], new RegExp(`${sel.replace(/\./g, '\\.')} \\{[^}]*min-height: 40px;`), sel);
  }
  assert.ok(tsx.includes('wifi-nav__btn tm-chip'));
});

test('text only: no innerHTML anywhere in the tab', () => {
  for (const f of ['TimeMachineView.tsx', 'tmLogic.ts', 'tmApi.ts', 'register.ts']) {
    const src = readFileSync(join(here, f), 'utf8');
    assert.doesNotMatch(src, /dangerouslySetInnerHTML|innerHTML|insertAdjacentHTML/, f);
  }
});
