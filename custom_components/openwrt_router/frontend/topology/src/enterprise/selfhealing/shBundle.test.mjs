// The BUILT bundle (../dist/topology-bundle.js, made by `npm run build` and
// committed): the Self-Healing tab adds no HTTP method other than GET.
// The counts are pinned against main's bundle at 06da693 (before the tab):
// "POST" 12, "PUT"/"DELETE"/"PATCH" 0, "GET" 29. The tab adds exactly two
// "GET" (fetch's method and hass.callApi('GET', …) in shApi.ts) and nothing
// else; when another tab changes these numbers on main, the pins move with
// that change, never with this tab.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const bundle = readFileSync(join(here, '../../../../dist/topology-bundle.js'), 'utf8');

const count = word => (bundle.match(new RegExp(`["'\`]${word}["'\`]`, 'g')) ?? []).length;

test('the bundle has the tab, and no other method string than main had', () => {
  assert.ok(bundle.includes('/api/openwrt_router/enterprise/selfhealing/v1'), 'the tab is in the bundle');
  assert.deepEqual(
    { GET: count('GET'), POST: count('POST'), PUT: count('PUT'), DELETE: count('DELETE'), PATCH: count('PATCH') },
    { GET: 29 + 2, POST: 12, PUT: 0, DELETE: 0, PATCH: 0 },
  );
});

test('the dev mock and its fixture are not in the bundle', () => {
  assert.ok(!bundle.includes('mock: request failed'));
  assert.ok(!bundle.includes('rem_00000000000000000000000000000002'));
});
