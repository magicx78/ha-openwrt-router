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
// the markup of the tab: the views and their shared pieces (tmUi.tsx, 1.52.0), the timeline first
const TSX_FILES = ['TimeMachineView.tsx', 'tmUi.tsx', 'TimeMachineState.tsx'];
const tsx = TSX_FILES.map(f => readFileSync(join(here, f), 'utf8')).join('\n');
const wifiCss = readFileSync(join(here, '../wifi/wifi.css'), 'utf8');
const cfgCss = readFileSync(join(here, '../config/config.css'), 'utf8');
const panelCss = readFileSync(join(here, '../../topology.css'), 'utf8');
const BREAKPOINT = Number(/@container tmlist \(max-width: (\d+)px\)/.exec(css)?.[1]);

const rule = sel => {
  const m = new RegExp(`(?:^|\\n)${sel.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')} \\{([^}]*)\\}`).exec(css);
  assert.ok(m, `rule ${sel}`);
  return m[1];
};

test('the block before the window and the list share one size container', () => {
  // 1.51.0 browser review: on .tm-list alone, the block beside it never became cards
  assert.match(rule('.tm-timeline'), /container: tmlist \/ inline-size;/);
  assert.doesNotMatch(rule('.tm-list'), /container/);
  const wrap = /<div className="tm-timeline">([\s\S]*?)<\/div>\n\s*\)\}/.exec(tsx);
  assert.ok(wrap, 'wrapper in the markup');
  assert.ok(wrap[1].includes('<SpansBlock') && wrap[1].includes('<TimelineList'));
});

test('below the width a row needs, every mark is a wrapping card with the title on its own line', () => {
  const m = /@container tmlist \(max-width: (\d+)px\) \{([\s\S]*?)\n\}/.exec(css);
  assert.ok(m, 'container rule present');
  // 1.50.0 review: at 720 px the source column wrapped at 1280 px windows; cards start at 860 px
  assert.ok(Number(m[1]) >= 860, `breakpoint ${m[1]} px below the row's width`);
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
  // nowrap only where a fixed column is measured to hold its text: the band
  // cell of a session row ("Band unbekannt", see the band test); never in the
  // timeline, and the session cards let it wrap again
  const nowrap = [...css.matchAll(/([^{}\n]+)\{[^}]*white-space: nowrap;/g)].map(m => m[1].trim());
  assert.deepEqual(nowrap, ['.tm-session__band']);
  assert.match(rule('.tm-chip'), /white-space: normal;/);
  // sum of the fixed columns stays under the breakpoint (12.5px font)
  const cols = /grid-template-columns: ([^;]+);/.exec(rule('.tm-mark'))[1];
  const em = [...cols.matchAll(/([\d.]+)em/g)].reduce((s, x) => s + Number(x[1]), 0);
  assert.ok(em * 12.5 + 5 * 12 + 20 < BREAKPOINT - 120, `fixed columns ${em}em leave room for the title`);
  // the source column holds its longest name ("Netzwerk-Ereignisse", 10.2em in
  // DejaVu Sans, one of the wider fallback fonts) on one line
  const last = /([\d.]+)em$/.exec(cols.trim());
  assert.ok(last && Number(last[1]) >= 11, `source column ${cols}`);
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

// WCAG 2.x contrast of the text colours on the chip background #0c1225
// (measured by the review; --surface over the panel background).
const lin = c => (c /= 255) <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4;
const lum = ([r, g, b]) => 0.2126 * lin(r) + 0.7152 * lin(g) + 0.0722 * lin(b);
const CHIP_BG = [0x0c, 0x12, 0x25];
const contrast = alpha => {
  const fg = CHIP_BG.map(c => 255 * alpha + c * (1 - alpha));
  return (lum(fg) + 0.05) / (lum(CHIP_BG) + 0.05);
};
const whiteAlpha = (src, scope, name) => {
  const block = new RegExp(`${scope.replace(/\./g, '\\.')} \\{[^}]*${name}:\\s*rgba\\(255, 255, 255, ([\\d.]+)\\)`).exec(src);
  assert.ok(block, `${scope} ${name}`);
  return Number(block[1]);
};

test('a locked chip and its note keep at least 4.5:1 on the chip background (review 1.50.0)', () => {
  const dis = rule('.tm-chip:disabled');
  assert.match(dis, /opacity: 1;/);
  assert.match(dis, /color: var\(--text-muted\);/);
  assert.match(dis, /border-style: dashed;/);
  assert.match(rule('.tm-chip__note'), /color: var\(--text-secondary\);/);
  // the tab root carries .cfg: --text-muted is config.css's 50 %, --text-secondary the panel's 55 %
  assert.ok(tsx.includes('className="cfg wifi tm"'));
  const muted = whiteAlpha(cfgCss, '.cfg', '--text-muted');
  const secondary = whiteAlpha(panelCss, '.topo-app', '--text-secondary');
  assert.equal(muted, 0.5);
  assert.equal(secondary, 0.55);
  assert.equal(contrast(muted).toFixed(2), '5.29');
  assert.equal(contrast(secondary).toFixed(2), '6.17');
  // before: the button's --text-secondary at opacity 0.55, the note --text-muted at 0.55
  assert.ok(contrast(secondary * 0.55) < 4.5 && contrast(muted * 0.55) < 4.5);
});

test('on phones the chips centre their text', () => {
  const m = /@media \(max-width: 600px\) \{([\s\S]*?)\n\}/.exec(css);
  assert.match(m[1], /\.tm-chip \{[^}]*text-align: center;/);
});

test('text only: no innerHTML anywhere in the tab', () => {
  for (const f of [...TSX_FILES, 'tmLogic.ts', 'tmState.ts', 'tmApi.ts', 'register.ts']) {
    const src = readFileSync(join(here, f), 'utf8');
    assert.doesNotMatch(src, /dangerouslySetInnerHTML|innerHTML|insertAdjacentHTML/, f);
  }
});

// ── 1.51.0: the block before the window and the client sessions ─────────

test('the block before the window gives the time column room for date and time', () => {
  const cols = /grid-template-columns: ([^;]+);/.exec(rule('.tm-spans .tm-mark'))[1];
  assert.match(cols, /^9\.5em /, '"21.11.2026, 14:03" in 12.5 px');
  assert.match(cols, /minmax\(0, 1fr\)/);
  // in the card layout the time is a flex item again (no grid columns)
  const m = /@container tmlist \(max-width: (\d+)px\) \{([\s\S]*?)\n\}/.exec(css);
  assert.match(m[2], /\.tm-mark \{[^}]*display: flex;/);
  const em = [...cols.matchAll(/([\d.]+)em/g)].reduce((s, x) => s + Number(x[1]), 0);
  assert.ok(em * 12.5 + 5 * 12 + 20 < BREAKPOINT - 60, `fixed columns ${em}em leave room for the title`);
});

test('sessions: a size container of their own; below its width every session is a wrapping card', () => {
  assert.match(rule('.tm-sessions'), /container: tmsessions \/ inline-size;/);
  const row = rule('.tm-session');
  assert.match(row, /minmax\(0, 1fr\)/);
  assert.match(rule('.tm-session > *'), /min-width: 0;/);
  const m = /@container tmsessions \(max-width: (\d+)px\) \{([\s\S]*?)\n\}/.exec(css);
  assert.ok(m, 'container rule present');
  const cols = /grid-template-columns: ([^;]+);/.exec(row)[1];
  const em = [...cols.matchAll(/([\d.]+)em/g)].reduce((s, x) => s + Number(x[1]), 0);
  assert.ok(em * 12.5 + 5 * 12 + 20 < Number(m[1]) - 100, `fixed columns ${em}em below the card width ${m[1]} px`);
  assert.match(m[2], /\.tm-session \{[^}]*display: flex;[^}]*flex-wrap: wrap;/);
  assert.match(m[2], /\.tm-session__client \{[^}]*flex: 1 1 100%;/);
  // markup order: start, duration, client, router, band, changes
  const order = ['tm-session__time', 'tm-session__dur', 'tm-session__client', 'tm-session__router', 'tm-session__band', 'tm-session__roam'];
  const at = order.map(c => tsx.indexOf(`"${c}"`));
  assert.ok(at.every(i => i > 0), 'all parts in the markup');
  assert.deepEqual([...at].sort((a, b) => a - b), at);
});

test('the view switch and the restart notice wrap like the rest', () => {
  assert.match(rule('.tm-restart'), /flex-wrap: wrap;/);
  assert.ok(tsx.includes('className="tm-chips tm-views"'));
  assert.match(rule('.tm-chips'), /flex-wrap: wrap;/);
});

// ── 1.51.0 browser review ─────────────────────────────────────────────────
// (The effective flex of the view switch is checked on the rendered markup
// in tmRender.test.mjs: "no item of a column flex box gets a fixed flex-basis".)

test('sessions: the band column holds "Band unbekannt" without breaking inside a word', () => {
  const cols = /grid-template-columns: ([^;]+);/.exec(rule('.tm-session'))[1];
  assert.equal(cols, '5em 9.5em minmax(0, 1fr) 9em 8.5em 6em');
  const band = Number(/([\d.]+)em [\d.]+em$/.exec(cols)[1]);
  // second browser review: "Band unbekannt" needs 102.9 px in 12.5 px (Firefox); 7em (87.5 px) broke it at the space
  assert.ok(band * 12.5 >= 102.9 + 2, `band column ${band * 12.5} px`);
  assert.match(rule('.tm-session__band'), /white-space: nowrap;/);
  const cards = /@container tmsessions \(max-width: (\d+)px\) \{([\s\S]*?)\n\}/.exec(css)[2];
  assert.match(cards, /\.tm-session__band \{ white-space: normal; \}/);
  // .tm breaks anywhere (no sideways scroll); the band cell breaks between words only
  assert.match(rule('.tm'), /overflow-wrap: anywhere;/);
  assert.match(rule('.tm-session__band'), /overflow-wrap: normal;/);
  assert.ok(css.indexOf('.tm-session__band { overflow-wrap: normal; white-space: nowrap; }') > css.indexOf('.tm {'));
  // the longer word "unbekannt" (9 letters, at most 0.62em each in 12.5 px) fits the 7em column
  assert.ok(9 * 0.62 < band);
});

test('focus inside the tab: a ring of at least 3:1 on the chip background, other tabs untouched', () => {
  const hex = s => [1, 3, 5].map(i => parseInt(s.slice(i, i + 2), 16));
  const ratio = (fg, bg) => { const [a, b] = [lum(fg), lum(bg)].sort((x, y) => y - x); return (a + 0.05) / (b + 0.05); };
  const m = /((?:\.tm [^{,]+:focus-visible,?\s*)+)\{ outline: 2px solid (#[0-9a-f]{6}); outline-offset: 2px; \}/.exec(css);
  assert.ok(m, 'focus rule of the tab');
  const sels = m[1].split(',').map(s => s.trim()).filter(Boolean);
  assert.deepEqual(sels, ['.tm .tm-chip:focus-visible', '.tm .tm-field select:focus-visible', '.tm .cfg-btn:focus-visible']);
  const ring = ratio(hex(m[2]), CHIP_BG);
  assert.equal(m[2], '#60a5fa');
  assert.equal(ring.toFixed(2), '7.32');
  assert.ok(ring >= 3);
  // before: the shared --border-focus, rgba(59, 130, 246, 0.5) over the chip background
  assert.match(panelCss, /--border-focus:\s+rgba\(59, 130, 246, 0\.5\);/);
  const old = ratio([59, 130, 246].map((c, i) => 0.5 * c + 0.5 * CHIP_BG[i]), CHIP_BG);
  assert.equal(old.toFixed(2), '2.16');
  // it wins over the shared rules by specificity (3 classes or 2 + element against 2), whatever the order
  assert.match(wifiCss, /\.wifi-nav__btn:focus-visible \{ outline: 2px solid var\(--border-focus\);/);
  assert.match(wifiCss, /\.wifi-field select:focus-visible \{ outline: 2px solid var\(--border-focus\);/);
  // every :focus-visible rule of this stylesheet is scoped to the tab root
  for (const [, sel] of css.matchAll(/([^{}\n]*:focus-visible)/g)) assert.match(sel.trim(), /^\.tm /, sel);
  // the shared focus rules of the other tabs still use the shared colour
  for (const [, sel, val] of (cfgCss + wifiCss).matchAll(/([^{}\n]*:focus-visible) \{ outline: 2px solid ([^;]+);/g)) assert.equal(val, 'var(--border-focus)', sel);
});

test('sessions: a long router name takes at most two lines in a row, all of it in a card', () => {
  const r = rule('.tm-session__router');
  assert.match(r, /display: -webkit-box;/);
  assert.match(r, /-webkit-box-orient: vertical;/);
  assert.match(r, /-webkit-line-clamp: 2;/);
  assert.match(r, /overflow: hidden;/);
  const m = /@container tmsessions \(max-width: (\d+)px\) \{([\s\S]*?)\n\}/.exec(css);
  assert.match(m[2], /\.tm-session__router \{ display: block; -webkit-line-clamp: unset; line-clamp: none; overflow: visible; \}/);
  // the whole name stays reachable in the title
  assert.match(tsx, /<span className="tm-session__router" title=\{router\}>\{router\}<\/span>/);
});

test('the block before the window turns into cards early enough: its title column never narrower than the list’s', () => {
  const FONT = 12.5, PAD = 20, GAPS = 5 * 12;
  const fixed = sel => [...(/grid-template-columns: ([^;]+);/.exec(rule(sel))[1]).matchAll(/([\d.]+)em/g)]
    .reduce((x, m) => x + Number(m[1]), 0) * FONT;
  const list = Number(/@container tmlist \(max-width: (\d+)px\) \{\n  \.tm-mark \{/.exec(css)[1]);
  const block = Number(/@container tmlist \(max-width: (\d+)px\) \{\n  \.tm-spans \.tm-mark \{/.exec(css)[1]);
  assert.equal(list, 860);
  assert.equal(block, 920);
  const listTitle = (list + 1) - PAD - GAPS - fixed('.tm-mark');
  const blockTitle = (block + 1) - PAD - GAPS - fixed('.tm-spans .tm-mark');
  assert.equal(listTitle, 281);
  assert.equal(blockTitle, 284.75);
  assert.ok(blockTitle >= listTitle);
  // and the cards of the block have the list's card shape
  const q = /@container tmlist \(max-width: 920px\) \{([\s\S]*?)\n\}/.exec(css)[1];
  assert.match(q, /\.tm-spans \.tm-mark \{ display: flex; flex-wrap: wrap;/);
  assert.match(q, /\.tm-spans \.tm-mark__main \{ flex: 1 1 100%;/);
});
