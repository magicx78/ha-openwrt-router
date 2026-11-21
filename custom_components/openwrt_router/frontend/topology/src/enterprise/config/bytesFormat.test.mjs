// 1.49.3 browser check P1: byte figures have a TB step everywhere
// (node:test, no dependencies). Invented values only.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { formatBytes } from '../../utils/format.ts';
import { fmtBytes } from '../traffic/trafficLogic.ts';
import { formatBytes as configBytes } from './configLogic.ts';

test('large byte counters read in TB, not as 987.654,3 GB', () => {
  for (const f of [formatBytes, fmtBytes]) {
    assert.equal(f(987_654_300_000_000), '987,7 TB');
    assert.equal(f(1_500_000_000_000), '1,5 TB');
    assert.equal(f(999_000_000_000), '999,0 GB');
    assert.equal(f(2_000_000), '2,0 MB');
  }
});

test('the archive size formatter also has GB and TB steps', () => {
  assert.equal(configBytes(5 * 1024 ** 3), '5 GB');
  assert.equal(configBytes(2.5 * 1024 ** 4), '2,5 TB');
  assert.equal(configBytes(1536), '1,5 KB');
});
