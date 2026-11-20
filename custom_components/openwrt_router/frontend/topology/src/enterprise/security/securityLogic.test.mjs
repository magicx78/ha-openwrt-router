// Tests of the pure Security Center logic (node:test, no dependencies).
// Node 24 strips the TypeScript types of the imported .ts files itself.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DEFAULT_FILTERS,
  DETECTION_LABEL,
  SecurityApiError,
  buildSettingsUpdate,
  detectionNotes,
  detectorSource,
  devicesObserved,
  draftFromSettings,
  errorInfo,
  factorText,
  filtersAreDefault,
  flaggedDeviceCount,
  formatRelativeTs,
  formatTs,
  incidentCounts,
  isLogSource,
  isRealMac,
  parseDetectionsView,
  parseIncidentDetail,
  parseOverview,
  parseSettingsView,
  portError,
  reasonText,
  routerIds,
  sanitizeName,
  scoreReasonText,
  scoreView,
  shortId,
  sortDevices,
  toOverviewFilters,
  unknownDeviceCount,
} from './securityLogic.ts';

const here = dirname(fileURLToPath(import.meta.url));

// ── Parsers: unknown stays unknown ───────────────────────────────────────

test('an empty or wrong answer parses to unknown values, never to 0 or healthy', () => {
  for (const bad of [null, undefined, 'x', 7, [], {}]) {
    const o = parseOverview(bad);
    assert.equal(o.enabled, false);
    assert.equal(o.active, false);
    assert.equal(o.score.score, null);
    assert.equal(o.score.coverage, null);
    assert.equal(o.coverage.value, null);
    assert.deepEqual(o.deviceCounts, { known: null, new: null, unrecognized: null, suspicious: null, quarantined: null });
    assert.equal(o.subnetZones, null);
    assert.deepEqual(o.incidents, []);
  }
});

test('score null / NaN / string is no rating; a number is kept', () => {
  assert.equal(parseOverview({ score: { score: null } }).score.score, null);
  assert.equal(parseOverview({ score: { score: 'high' } }).score.score, null);
  assert.equal(parseOverview({ score: { score: Number.NaN } }).score.score, null);
  assert.equal(parseOverview({ score: { score: 81 } }).score.score, 81);
});

test('a factor that is not assessable never carries a deduction, even if the server sends one', () => {
  const o = parseOverview({ score: { score: 70, factors: [
    { id: 'network_activity', assessable: false, deduction: 0, weight: 15, missing: ['security.center.firewall_log'] },
    { id: 'active_incidents', assessable: true, deduction: 4, weight: 40, partial: true, limitations: ['capacity'] },
    { assessable: true },
  ] } });
  assert.equal(o.score.factors.length, 2);
  assert.equal(o.score.factors[0].deduction, null);
  assert.deepEqual(factorText(o.score.factors[0]), { text: 'nicht bewertbar', tone: 'muted' });
  assert.equal(factorText(o.score.factors[1]).text, '−4 von 40 Punkte');
});

test('a zero deduction is "kein Abzug" only when assessable; partial is not shown as plain clean', () => {
  const ok = { id: 'a', assessable: true, deduction: 0, weight: 5, partial: false, limitations: [], missing: [] };
  assert.deepEqual(factorText(ok), { text: 'kein Abzug', tone: 'ok' });
  const partial = { ...ok, partial: true };
  assert.equal(factorText(partial).tone, 'info');
  assert.match(factorText(partial).text, /eingeschränkt/);
  assert.equal(factorText({ ...ok, deduction: null }).tone, 'muted');
});

test('incidents: id is required, lists are strings only, masked fields stay as sent', () => {
  const o = parseOverview({
    incidents: [
      { id: 'sec_1', title: '<img src=x onerror=alert(1)>', severity: 'critical', status: 'open', evidence: ['a=1', 5, null, 'b=2'],
        client_ref: 'cli_abc', has_client: true, linked_incident_ids: ['inc_1', 3], count: 'many' },
      { title: 'no id' },
      'junk',
    ],
  });
  assert.equal(o.incidents.length, 1);
  const i = o.incidents[0];
  assert.equal(i.title, '<img src=x onerror=alert(1)>'); // kept as plain text, rendered as a text node
  assert.deepEqual(i.evidence, ['a=1', 'b=2']);
  assert.deepEqual(i.linkedIncidentIds, ['inc_1']);
  assert.equal(i.count, null);
  assert.equal(i.client, null);
  assert.equal(i.clientRef, 'cli_abc');
});

test('devices: name_set survives for non-admins, observed only false when explicitly false', () => {
  const o = parseOverview({ devices: [
    { mac: 'cli_x1', ip: 'ipa_x1', hostname: 'hst_x1', name: null, name_set: true, state: 'known', observed: false },
    { mac: 'cli_x2', state: 'bogus' },
    { mac: '02:00:00:00:00:09' },
  ] });
  assert.equal(o.devices[0].nameSet, true);
  assert.equal(o.devices[0].observed, false);
  assert.equal(o.devices[1].observed, true);
  assert.equal(o.devices[1].state, 'bogus');
  assert.equal(o.devices[2].state, null);
});

test('detections: reason tokens are split, flags are strict booleans', () => {
  const v = parseDetectionsView({
    detections: [
      { id: 'fw_blocked', availability: 'limited', reason: 'capacity,dest_zone_unknown', missing: ['security.center.firewall_log'], limitations: ['capacity'], learning: 'yes', format_unconfirmed: true },
      { availability: 'available' },
    ],
    sources: { rtr_a: { 'config.drift': { source: 'config.drift', availability: 'available', reason: 'ok', last_ok: 5 }, junk: 3 } },
    log_path: { setting: 'syslog', status: [{ source: 'security.center.firewall_log', availability: 'not_available', reason: 'port_in_use' }], receiver: { listening: false, reason: 'port_in_use', port: 5514, senders: 0 } },
  });
  assert.equal(v.detections.length, 1);
  assert.deepEqual(v.detections[0].reason, ['capacity', 'dest_zone_unknown']);
  assert.equal(v.detections[0].learning, false);
  assert.equal(v.detections[0].formatUnconfirmed, true);
  assert.deepEqual(Object.keys(v.sources), ['rtr_a']);
  assert.equal(v.sources.rtr_a.length, 1);
  assert.equal(v.logPath.receiver.listening, false);
  assert.equal(parseDetectionsView(null).detections.length, 0);
});

test('settings view: counts of maps, can_edit strict, unknown receiver stays null', () => {
  const v = parseSettingsView({ settings: { enabled: true, log_path: 'off', syslog_port: 5514, keep_dns_names: false, thresholds: { dns_rate: 50 }, subnet_zones: {} }, subnet_zone_count: 3, active: true, can_edit: true });
  assert.equal(v.settings.thresholdCount, 1);
  assert.equal(v.settings.zoneCount, 0);
  assert.equal(v.subnetZoneCount, 3);
  assert.equal(v.canEdit, true);
  assert.equal(v.receiver, null);
  const bad = parseSettingsView({ settings: { enabled: 'true', syslog_port: '5514' }, can_edit: 'yes' });
  assert.equal(bad.settings.enabled, false);
  assert.equal(bad.settings.syslogPort, null);
  assert.equal(bad.canEdit, false);
});

test('incident detail needs an incident; an answer without one is null', () => {
  assert.equal(parseIncidentDetail({ admin_view: true }), null);
  const d = parseIncidentDetail({ admin_view: true, incident: { id: 'sec_9' }, timeline: [{ ts: 5, text: 't' }], now: 10 });
  assert.equal(d.incident.id, 'sec_9');
  assert.equal(d.timeline.length, 1);
});

// ── Score / counts / availability views ──────────────────────────────────

test('a null score is "Keine Bewertung möglich" in the unknown tone, never a number or green', () => {
  const v = scoreView({ score: null, coverage: 0, cap: 0, reason: null, factors: [], routers: 0 });
  assert.equal(v.known, false);
  assert.equal(v.value, null);
  assert.equal(v.tone, 'muted');
  assert.equal(v.headline, 'Keine Bewertung möglich');
  assert.match(v.note, /nicht, dass alles in Ordnung ist/);
});

test('a known score is green only with full coverage; capped scores stay neutral and say why', () => {
  const full = scoreView({ score: 95, coverage: 100, cap: 100, reason: 'complete', factors: [], routers: 1 });
  assert.equal(full.tone, 'ok');
  assert.equal(full.note, null);
  const partial = scoreView({ score: 79, coverage: 57, cap: 79, reason: null, factors: [], routers: 1 });
  assert.equal(partial.tone, 'info');
  assert.match(partial.note, /Höchstens 79 von 100/);
  assert.equal(scoreView({ score: 60, coverage: 57, cap: 79, reason: null, factors: [], routers: 1 }).tone, 'warn');
  assert.equal(scoreView({ score: 60, coverage: 100, cap: 100, reason: null, factors: [], routers: 1 }).tone, 'warn');
  assert.equal(scoreView({ score: 30, coverage: 100, cap: 100, reason: null, factors: [], routers: 1 }).tone, 'critical');
  // coverage unknown + score present: never green
  assert.notEqual(scoreView({ score: 99, coverage: null, cap: null, reason: null, factors: [], routers: null }).tone, 'ok');
});

test('the backend reason strings map to German; unknown ones to nothing', () => {
  assert.match(scoreReasonText('capped at 79: partial coverage'), /Auf 79 begrenzt/);
  assert.match(scoreReasonText('capped at 99: a factor is not assessable'), /nicht bewertbar/);
  assert.match(scoreReasonText('unknown: no usable data source'), /Keine nutzbare Datenquelle/);
  assert.match(scoreReasonText('complete'), /Alle erwarteten/);
  assert.equal(scoreReasonText('something new'), null);
  assert.equal(scoreReasonText(null), null);
});

test('incident counts: resolved ones do not count, an unknown status stays visible', () => {
  const mk = (status, severity) => ({ id: `sec_${status}${severity}`, status, severity });
  const c = incidentCounts([mk('open', 'critical'), mk('confirmed', 'critical'), mk('resolved', 'critical'), mk(null, 'warning'), mk('open', 'info')]);
  assert.deepEqual(c, { active: 4, critical: 2 });
});

test('device counts: unknown stays unknown; the sum covers every state that is not "known"', () => {
  assert.equal(unknownDeviceCount({ known: null, new: null, unrecognized: null, suspicious: null, quarantined: null }), null);
  assert.equal(unknownDeviceCount({ known: 5, new: 1, unrecognized: 2, suspicious: 1, quarantined: 0 }), 4);
  assert.equal(flaggedDeviceCount({ known: 5, new: 1, unrecognized: 2, suspicious: 1, quarantined: 1 }), 2);
  assert.equal(flaggedDeviceCount({ known: 1, new: 0, unrecognized: 0, suspicious: null, quarantined: null }), null);
});

test('the device list counts as observed only while a device source is available', () => {
  assert.equal(devicesObserved({ value: 50, available: ['data.hostapd_clients'], stale: [], missing: [] }), true);
  assert.equal(devicesObserved({ value: 50, available: [], stale: ['data.hostapd_clients'], missing: [] }), false);
  assert.equal(devicesObserved({ value: null, available: [], stale: [], missing: [] }), false);
});

test('detection notes say limited, learning and "Format unbestätigt" in German', () => {
  const notes = detectionNotes({ id: 'fw_blocked', availability: 'limited', reason: [], missing: [], limitations: ['capacity', 'strange_token'], learning: true, formatUnconfirmed: true });
  assert.equal(notes.length, 4);
  assert.match(notes[0], /Speichergrenze/);
  assert.equal(notes[1], 'strange_token'); // unknown token shown as itself
  assert.match(notes[2], /gelernt/);
  assert.match(notes[3], /Format unbestätigt/);
  assert.deepEqual(detectionNotes({ id: 'x', availability: 'available', reason: [], missing: [], limitations: [], learning: false, formatUnconfirmed: false }), []);
});

test('reason tokens: known ones are German, unknown ones are shown as themselves', () => {
  assert.equal(reasonText(['no_data_yet', 'port_in_use']), 'noch keine Daten empfangen; Port ist belegt');
  assert.equal(reasonText(['brand_new']), 'brand_new');
});

test('detector -> data source is derived by prefix; log sources are marked forgeable', () => {
  assert.equal(detectorSource('wifi_auth_repeat'), 'security.center.wifi_events');
  assert.equal(detectorSource('fw_blocked'), 'security.center.firewall_log');
  assert.equal(detectorSource('dns_rate'), 'security.center.dns_query_log');
  assert.equal(detectorSource('vlan_segmentation_drift'), 'config.drift');
  assert.equal(detectorSource('other'), null);
  assert.equal(isLogSource('security.center.firewall_log'), true);
  assert.equal(isLogSource('config.drift'), false);
  assert.equal(isLogSource(null), false);
});

test('every detection title of the backend has a German label here (drift guard)', () => {
  const py = join(here, '..', '..', '..', '..', 'security_center.py');
  if (!existsSync(py)) return; // not run from inside the repo
  const src = readFileSync(py, 'utf8');
  const block = /TITLES: Mapping\[str, str\] = \{([\s\S]*?)\n\}/.exec(src);
  assert.ok(block, 'TITLES block found');
  const keys = [...block[1].matchAll(/"([a-z_]+)":/g)].map(m => m[1]);
  assert.ok(keys.length >= 10);
  for (const k of keys) assert.ok(DETECTION_LABEL[k], `label for ${k}`);
});

// ── Errors ───────────────────────────────────────────────────────────────

test('errors map from status and code; the server message is never used', () => {
  const info = s => errorInfo(new SecurityApiError(s, 'x'));
  assert.equal(info(403).kind, 'forbidden');
  assert.equal(info(409).kind, 'disabled');
  assert.equal(info(410).kind, 'gone');
  assert.equal(info(410).retry, true);
  assert.equal(info(413).kind, 'too_large');
  assert.equal(info(503).kind, 'unavailable');
  assert.equal(info(404).kind, 'not_found');
  assert.equal(info(400).kind, 'invalid');
  assert.equal(info(401).kind, 'session');
  assert.equal(info(500).kind, 'other');
  assert.equal(info(500).retry, true);
  assert.match(errorInfo(new SecurityApiError(503, 'no_core')).message, /Enterprise Core/);
  assert.match(errorInfo(new SecurityApiError(404, 'unknown_incident')).message, /nicht mehr vorhanden/);
  assert.equal(errorInfo(new SecurityApiError(null, 'not_connected')).kind, 'other');
  assert.equal(errorInfo(new TypeError('Failed to fetch')).kind, 'network');
  assert.equal(errorInfo(new Error('<script>x</script>')).kind, 'other');
  assert.doesNotMatch(errorInfo(new Error('<script>x</script>')).message, /script/);
});

// ── Devices and names ────────────────────────────────────────────────────

test('only a real MAC is writable; pseudonyms and the mask are not', () => {
  assert.equal(isRealMac('02:00:00:00:00:01'), true);
  assert.equal(isRealMac('02:00:00:00:00:0G'), false);
  assert.equal(isRealMac('cli_abc123'), false);
  assert.equal(isRealMac('***'), false);
  assert.equal(isRealMac(null), false);
});

test('names: trimmed, 1 to 64 characters, no control characters', () => {
  assert.equal(sanitizeName('  Telefon  '), 'Telefon');
  assert.equal(sanitizeName(''), null);
  assert.equal(sanitizeName('   '), null);
  assert.equal(sanitizeName('a'.repeat(64)), 'a'.repeat(64));
  assert.equal(sanitizeName('a'.repeat(65)), null);
  assert.equal(sanitizeName('bad\u0007name'), null);
  assert.equal(sanitizeName('line\nbreak'), null);
});

test('devices sort by trust (indicators first), then by last seen; unknown states last', () => {
  const mk = (mac, state, lastSeen) => ({ mac, state, lastSeen });
  const out = sortDevices([mk('a', 'known', 10), mk('b', 'new', 5), mk('c', 'suspicious', 1), mk('d', null, 99), mk('e', 'new', 9)]);
  assert.deepEqual(out.map(d => d.mac), ['c', 'e', 'b', 'a', 'd']);
});

// ── Time ─────────────────────────────────────────────────────────────────

test('time helpers: null stays a dash', () => {
  assert.equal(formatTs(null), '–');
  assert.equal(formatTs(Number.NaN), '–');
  assert.equal(formatRelativeTs(null, 0), '–');
  const nowMs = 1_800_000_000_000;
  assert.equal(formatRelativeTs(1_800_000_000 - 120, nowMs), 'vor 2 min');
  assert.equal(formatRelativeTs(1_800_000_000 - 3 * 3600, nowMs), 'vor 3 h');
  assert.equal(formatRelativeTs(1_800_000_000, nowMs), 'jetzt');
  assert.equal(shortId('rtr_0123456789abcdef'), 'rtr_012345…');
  assert.equal(shortId(null), '–');
});

// ── Filters ──────────────────────────────────────────────────────────────

test('timeline filters: default is "no filter"; the request carries only what is set', () => {
  assert.equal(filtersAreDefault(DEFAULT_FILTERS), true);
  assert.equal(filtersAreDefault({ ...DEFAULT_FILTERS, severity: 'warning' }), false);
  assert.deepEqual(toOverviewFilters(DEFAULT_FILTERS, 1000), {});
  assert.deepEqual(toOverviewFilters({ range: '1h', routerId: 'rtr_1', category: 'wifi', severity: 'critical', client: 'cli_x' }, 10_000), {
    since: 6400, routerId: 'rtr_1', category: 'wifi', severity: 'critical', client: 'cli_x',
  });
  assert.equal(toOverviewFilters({ ...DEFAULT_FILTERS, severity: 'nonsense' }, 1).severity, undefined);
});

test('router ids come from incidents, timeline and detection sources, sorted and unique', () => {
  const o = parseOverview({
    incidents: [{ id: 'sec_1', router_id: 'rtr_b' }],
    timeline: [{ router_id: 'rtr_a' }, { router_id: 'rtr_b' }, {}],
  });
  assert.deepEqual(routerIds(o, null), ['rtr_a', 'rtr_b']);
  assert.deepEqual(routerIds(o, { enabled: true, active: true, detections: [], sources: { rtr_c: [] }, logPath: { setting: null, status: [], receiver: null } }), ['rtr_a', 'rtr_b', 'rtr_c']);
});

// ── Settings form ────────────────────────────────────────────────────────

const SETTINGS = { enabled: true, logPath: 'off', syslogPort: 5514, keepDnsNames: false, thresholdCount: 0, zoneCount: 0 };

test('settings update sends only the changed fields', () => {
  const draft = draftFromSettings(SETTINGS);
  assert.deepEqual(buildSettingsUpdate(SETTINGS, draft), { update: {}, error: null });
  assert.deepEqual(buildSettingsUpdate(SETTINGS, { ...draft, enabled: false }).update, { enabled: false });
  assert.deepEqual(buildSettingsUpdate(SETTINGS, { ...draft, keepDnsNames: true }).update, { keep_dns_names: true });
  assert.deepEqual(buildSettingsUpdate(SETTINGS, { ...draft, logPath: 'syslog' }).update, { log_path: 'syslog' });
  assert.deepEqual(buildSettingsUpdate(SETTINGS, { ...draft, logPath: 'syslog', syslogPort: '6514' }).update, { log_path: 'syslog', syslog_port: 6514 });
});

test('the collector can never be sent', () => {
  const r = buildSettingsUpdate(SETTINGS, { ...draftFromSettings(SETTINGS), logPath: 'collector' });
  assert.deepEqual(r.update, {});
  assert.match(r.error, /Collector/);
  // already set to collector elsewhere: saving other fields does not resend it
  const cur = { ...SETTINGS, logPath: 'collector' };
  assert.deepEqual(buildSettingsUpdate(cur, { ...draftFromSettings(cur), keepDnsNames: true }), { update: { keep_dns_names: true }, error: null });
});

test('the syslog port is checked (1024-65535) only while syslog is chosen', () => {
  assert.equal(portError('5514'), null);
  assert.match(portError('80'), /zwischen 1024 und 65535/);
  assert.match(portError('70000'), /zwischen/);
  assert.match(portError('abc'), /Portnummer/);
  assert.match(portError(''), /Portnummer/);
  const syslog = { ...SETTINGS, logPath: 'syslog' };
  assert.match(buildSettingsUpdate(syslog, { ...draftFromSettings(syslog), syslogPort: '22' }).error, /zwischen/);
  // not syslog: a garbage port is ignored, not sent
  assert.deepEqual(buildSettingsUpdate(SETTINGS, { ...draftFromSettings(SETTINGS), syslogPort: 'x' }), { update: {}, error: null });
});

// ── Source guards: untrusted text, privacy, wording ──────────────────────

const SRC = readdirSync(here).filter(f => /\.(ts|tsx)$/.test(f)).map(f => [f, readFileSync(join(here, f), 'utf8')]);

test('no file of the tab renders HTML from the server, logs, or stores anything', () => {
  assert.ok(SRC.length >= 12);
  for (const [name, text] of SRC) {
    assert.doesNotMatch(text, /dangerouslySetInnerHTML/, `${name}: dangerouslySetInnerHTML`);
    assert.doesNotMatch(text, /\binnerHTML\b/, `${name}: innerHTML`);
    assert.doesNotMatch(text, /console\.(log|info|warn|error|debug)/, `${name}: console`);
    assert.doesNotMatch(text, /(localStorage|sessionStorage|indexedDB|document\.cookie)/, `${name}: browser storage`);
  }
});

test('the user-facing texts never say "Angriff" or "Einbruch" as a verdict', () => {
  for (const [name, text] of SRC) {
    const noComments = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
    assert.doesNotMatch(noComments, /\b(Angriff|Angriffe|Einbruch|Einbrüche|Hacker|gehackt)\b/i, name);
  }
});
