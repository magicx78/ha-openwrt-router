// Narrow layout of the "Self-Healing" tab: wrapping rows, cards below the
// width of a record row (container query, the Time Machine pattern), no
// sideways scroll, touch-size controls on phones (stylesheet and markup
// checks, node:test, no dependencies).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const css = readFileSync(join(here, 'selfhealing.css'), 'utf8');
const tsx = readFileSync(join(here, 'SelfHealingView.tsx'), 'utf8');

const rule = sel => {
  const m = new RegExp(`(?:^|\\n)${sel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} \\{([^}]*)\\}`).exec(css);
  assert.ok(m, `rule ${sel}`);
  return m[1];
};
const block = head => {
  const at = css.indexOf(head);
  assert.ok(at >= 0, head);
  let depth = 0;
  for (let i = css.indexOf('{', at); i < css.length; i++) {
    if (css[i] === '{') depth++;
    else if (css[i] === '}' && --depth === 0) return css.slice(at, i + 1);
  }
  throw new Error(`unclosed ${head}`);
};

test('the tab loads the shared stylesheets and its own, like the Time Machine', () => {
  for (const s of ["'../config/config.css?inline'", "'../wifi/wifi.css?inline'", "'./selfhealing.css?inline'"]) assert.ok(tsx.includes(s), s);
  assert.match(tsx, /className="cfg wifi sh"/);
});

test('nothing forces a sideways scroll', () => {
  assert.match(rule('.sh'), /min-width: 0;/);
  assert.match(rule('.sh'), /max-width: 100%;/);
  assert.match(rule('.sh'), /overflow-wrap: anywhere;/);
  assert.doesNotMatch(css, /overflow-x:\s*(auto|scroll)/);
  // nowrap only for the pills of the wide record row (its columns fit them; the card layout wraps again)
  assert.deepEqual([...css.matchAll(/([^{}\n]+)\{[^}]*white-space:\s*nowrap/g)].map(m => m[1].trim()), ['.sh-row .sh-badge']);
  assert.doesNotMatch(css, /(?<![-\w])width:\s*\d{3,}px/);
  assert.doesNotMatch(css, /min-width:\s*[1-9]\d*px/);
  for (const sel of ['.sh-filters', '.sh-chips', '.sh-field']) assert.match(rule(sel), /flex-wrap: wrap;/, sel);
  for (const sel of ['.sh-tiles', '.sh-cards']) assert.match(rule(sel), /minmax\(min\(100%, \d+px\), 1fr\)/, sel);
  for (const sel of ['.sh-row', '.sh-history__item', '.sh-fact']) assert.match(rule(sel), /minmax\(0, 1fr\)/, sel);
  assert.match(rule('.sh-row > *'), /min-width: 0;/);
  // shared badges may not keep a long state on one line
  assert.match(rule('.sh .cfg-badge'), /white-space: normal;/);
});

test('below the width a record row needs, the row becomes a wrapping card', () => {
  assert.match(rule('.sh-records'), /container: shlist \/ inline-size;/);
  const m = /@container shlist \(max-width: (\d+)px\)/.exec(css);
  assert.ok(m, 'container breakpoint');
  // the fixed columns at 12.5 px, five 12 px gaps, the button (about 10em) and at least 15em for the title
  const ems = [...rule('.sh-row').match(/grid-template-columns: ([^;]+);/)[1].matchAll(/([\d.]+)em/g)].map(x => Number(x[1]));
  const need = (ems.reduce((a, b) => a + b, 0) + 10 + 15) * 12.5 + 5 * 12;
  assert.ok(Number(m[1]) >= need, `breakpoint ${m[1]} px at least the row width ${need} px`);
  const b = block('@container shlist');
  assert.match(b, /\.sh-row \{[^}]*display: flex;[^}]*flex-wrap: wrap;/);
  assert.match(b, /\.sh-row__main \{[^}]*flex: 1 1 100%;/);
  assert.match(b, /\.sh-history__item \{[^}]*flex-wrap: wrap;/);
});

test('on phones every control is at least 40 px tall and facts are one column', () => {
  const b = block('@media (max-width: 600px)');
  assert.match(b, /\.sh-chip \{[^}]*min-height: 40px;/);
  assert.match(b, /\.sh-field select \{[^}]*min-height: 40px;/);
  assert.match(b, /\.sh \.cfg-btn \{[^}]*min-height: 40px;/);
  assert.match(b, /\.sh-fact, \.sh-card \.sh-fact \{[^}]*grid-template-columns: minmax\(0, 1fr\);/);
});

test('a flex-basis sits only on items of a row flex box (never a height in the .cfg column)', () => {
  // .cfg is a column flex box: a flex-basis on its direct children would be a height
  for (const sel of ['.sh-section', '.sh-observe, .sh-off, .sh-error', '.sh-stand']) {
    const r = css.includes(`\n${sel} {`) ? rule(sel) : '';
    assert.doesNotMatch(r, /flex:\s*\d/, sel);
  }
});

test('unknown is muted text, never a status colour', () => {
  assert.match(rule('.sh-unknown'), /color: var\(--text-muted\);/);
  assert.doesNotMatch(rule('.sh-unknown'), /green|--ok/);
  assert.doesNotMatch(css, /--green/);
});

test('focus is visible on every control of the tab', () => {
  assert.match(css, /\.sh \.sh-chip:focus-visible,\n\.sh \.sh-field select:focus-visible,\n\.sh \.cfg-btn:focus-visible \{ outline: 2px solid #60a5fa;/);
});

test('P3-10: in the wide row a pill never wraps inside itself', () => {
  // the longest labels, measured in Chrome at 12.5 px (cfg-badge 10.5 px, padding 7 px):
  // state 17.45em "Wiederherstellung von Hand nötig", risk 10.87em "Risiko 0 – nur lesend"
  const cols = rule('.sh-row').match(/grid-template-columns: ([^;]+);/)[1].split(/\s+(?![^(]*\))/);
  assert.equal(cols.length, 6);
  const em = c => Number(/^([\d.]+)em$/.exec(c)?.[1] ?? NaN);
  assert.ok(em(cols[1]) >= 17.5, `state column ${cols[1]}`);
  assert.ok(em(cols[4]) >= 11, `risk column ${cols[4]}`);
  assert.match(rule('.sh-row .sh-badge'), /white-space: nowrap;/);
  assert.match(block('@container shlist'), /\.sh-row \.sh-badge \{ white-space: normal; \}/);
});

test('P3-2: an outdated block is visibly framed and labelled', () => {
  assert.match(rule('.sh-stale'), /border: 1px dashed rgba\(245, 158, 11, 0\.7\);/);
  assert.doesNotMatch(rule('.sh-stale'), /flex:\s*\d/);
  assert.match(rule('.sh-stale__label'), /color: var\(--amber\);/);
  assert.match(tsx, /<strong className="sh-stale__label">\{STALE_LABEL\}<\/strong>/);
});
