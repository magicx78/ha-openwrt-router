// 1.49.3 browser check P3: the history tables become cards when narrow,
// after the Config Manager's container-query pattern (stylesheet and markup
// checks, node:test, no dependencies).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const css = readFileSync(join(here, 'diagnostics.css'), 'utf8');
const tsx = readFileSync(join(here, 'DiagHistory.tsx'), 'utf8');

test('the history table wrapper is a size container', () => {
  assert.match(css, /\.dg-table-wrap \{[^}]*container: dghist \/ inline-size;/);
});

test('below the width the six columns need, rows are cards with labelled values', () => {
  const m = /@container dghist \(max-width: (\d+)px\) \{([\s\S]*?)\n\}/.exec(css);
  assert.ok(m, 'container rule present');
  const bp = Number(m[1]);
  assert.ok(bp >= 520, `breakpoint ${bp} px below the table's width`);
  const body = m[2];
  assert.match(body, /\.dg-table thead \{ display: none; \}/);
  assert.match(body, /\.dg-table tr \{[^}]*display: grid;/);
  assert.match(body, /\.dg-table td::before \{[^}]*content: attr\(data-label\);/);
  for (const name of ['Latenz (Mittel)', 'Jitter', 'Verlust', 'Lücken', 'Abdeckung']) {
    assert.ok(tsx.includes(`'${name}'`), `label ${name} in the markup`);
  }
  assert.match(tsx, /data-label=\{/);
});
