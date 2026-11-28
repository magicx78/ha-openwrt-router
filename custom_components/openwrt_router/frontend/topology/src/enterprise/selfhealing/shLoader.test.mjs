// Loader of the "Self-Healing" tab (node:test, no dependencies): one
// AbortController per load, a poll never starts while a load runs, a load
// asked for by hand aborts the running one, and unmount (dispose) aborts and
// reports nothing more.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createShLoader } from './shLoader.ts';

/** An api whose answers the test releases by hand; every call records its signal. */
function world() {
  const calls = [];
  const call = name => (...args) => {
    const signal = args.at(-1);
    let resolve;
    const p = new Promise(r => { resolve = r; });
    calls.push({ name, args, signal, resolve });
    return p;
  };
  const api = {
    overview: call('overview'), actions: call('actions'), settings: call('settings'),
    action: call('action'), plan: call('plan'),
  };
  return { api, calls, answerAll: (from = 0) => calls.slice(from).forEach(c => c.resolve(c.name)) };
}

const flush = () => new Promise(r => setTimeout(r, 0));

test('a poll never starts while a load runs; one AbortController per load', async () => {
  const w = world();
  const results = [];
  let starts = 0;
  const l = createShLoader({ api: w.api, isAdmin: true, onStart: () => { starts++; }, onResult: r => results.push(r) });
  assert.equal(l.load(null, 'now'), true);
  assert.equal(l.running, true);
  assert.deepEqual(w.calls.map(c => c.name), ['overview', 'actions', 'settings']);
  const signal = w.calls[0].signal;
  assert.ok(signal instanceof AbortSignal);
  assert.ok(w.calls.every(c => c.signal === signal), 'all requests of a load share its signal');
  assert.equal(l.load(null, 'poll'), false, 'no second load while one runs');
  assert.equal(w.calls.length, 3);
  w.answerAll();
  await flush();
  assert.equal(results.length, 1);
  assert.equal(results[0].overview.ok, true);
  assert.equal(l.running, false);
  assert.equal(l.load(null, 'poll'), true, 'the next poll runs once the load is done');
  assert.notEqual(w.calls[3].signal, signal, 'a new load has a new controller');
  assert.equal(starts, 2);
});

test('a load asked for by hand aborts the running one; its answers are dropped', async () => {
  const w = world();
  const results = [];
  const l = createShLoader({ api: w.api, isAdmin: true, onStart: () => {}, onResult: r => results.push(r) });
  l.load(null, 'now');
  const first = w.calls[0].signal;
  const ID = `rem_${'a'.repeat(32)}`;
  assert.equal(l.load(ID, 'now'), true);
  assert.equal(first.aborted, true, 'the running load is aborted first');
  assert.deepEqual(w.calls.slice(3).map(c => c.name), ['overview', 'actions', 'settings', 'action', 'plan']);
  assert.deepEqual(w.calls.find(c => c.name === 'action').args[0], ID);
  w.answerAll();
  await flush();
  assert.equal(results.length, 1, 'only the newer load reports');
  assert.equal(results[0].selected, ID);
});

test('dispose (unmount) aborts the running load and reports nothing after it', async () => {
  const w = world();
  const results = [];
  const l = createShLoader({ api: w.api, isAdmin: true, onStart: () => {}, onResult: r => results.push(r) });
  l.load(null, 'now');
  l.dispose();
  assert.equal(w.calls[0].signal.aborted, true);
  w.answerAll();
  await flush();
  assert.equal(results.length, 0);
  assert.equal(l.load(null, 'now'), false, 'a disposed loader starts nothing');
  assert.equal(w.calls.length, 3);
});

test('a non-admin asks for the overview only', async () => {
  const w = world();
  const l = createShLoader({ api: w.api, isAdmin: false, onStart: () => {}, onResult: () => {} });
  l.load(`rem_${'a'.repeat(32)}`, 'now');
  assert.deepEqual(w.calls.map(c => c.name), ['overview']);
  l.dispose();
});
