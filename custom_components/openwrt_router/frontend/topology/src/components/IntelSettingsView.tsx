/**
 * IntelSettingsView — thresholds, exclusions and maintenance of the network
 * intelligence (Diagnose tab → Einstellungen, P7).
 *
 * Reads GET /intelligence/settings; saving sends only the changed values
 * (POST, admin only). The server checks them with the bounds of
 * merge_settings and answers 400 with a list of errors.
 */

import React, { useEffect, useMemo, useState } from 'react';
import type { IntelApi } from '../api';
import type { IntelSettingsResponse, IntelSettingsTree } from '../types';
import { SEVERITY_LABEL, errorMessage, formatTs, typeLabel } from '../utils/intel';

type Tree = IntelSettingsTree;
type Path = string[];

const SEVERITY_KEYS = new Set(['severity', 'notify_min_severity', 'inferred_severity']);
const FIXED_KEYS = new Set(['schema', 'mode', 'stay_open']);
const RULE_META = new Set(['auto_resolve', 'ignored']);

const FIELD_LABEL: Record<string, string> = {
  raise: 'Auslösen ab',
  clear: 'Aufheben bei / nach',
  count: 'Anzahl',
  window: 'Zeitfenster (s)',
  cooldown: 'Cooldown (s)',
  debounce: 'Entprellung (Messungen)',
  severity: 'Schweregrad',
  hold: 'Haltezeit (s)',
  mode: 'Art',
  duration: 'Dauer (s)',
  max_gap: 'Max. Lücke (s)',
  clear_below: 'Aufheben unter',
  min_clients: 'Min. Clients',
  min_ratio: 'Min. Anteil (0–1)',
  ratio_min_clients: 'Anteil ab Clients',
  weak_dbm: 'Schwach ab (dBm)',
  clear_dbm: 'Gut ab (dBm)',
  min_available_mb: 'Min. frei (MB)',
  stay_open: 'Bleibt offen ohne Daten',
  services: 'Dienste',
  escalate: 'Eskalation',
  value: 'Wert',
  min_count: 'Min. Anzahl',
  min_packets: 'Min. Pakete',
  interval: 'Intervall (s)',
  ack_grace: 'Kulanz (s)',
  dhcp_missing_after: 'Ohne DHCP nach (s)',
  warn_clients_per_ap: 'Warnung ab Clients je AP',
  inferred_severity: 'Schweregrad (abgeleitet)',
  inferred_confidence: 'Konfidenz (abgeleitet)',
  states: 'Zustände',
  weights: 'Gewichte',
  penalty: 'Abzug je Incident',
  min_coverage: 'Min. Abdeckung (0–1)',
  min_area_coverage: 'Min. Bereichsabdeckung (0–1)',
  wifi: 'WLAN',
  system: 'System',
  lan: 'LAN',
  wan: 'WAN',
  dhcp_dns: 'DHCP/DNS',
  notify_min_severity: 'HA-Ereignis ab',
  retention_days: 'Aufbewahrung (Tage)',
  max_events: 'Max. gespeicherte Ereignisse',
  critical: 'kritisch',
  warning: 'Warnung',
  info: 'Info',
};

const MODE_LABEL: Record<string, string> = { level: 'Messwert', window: 'Zählfenster', event: 'Ereignis' };

function isObj(v: unknown): v is Tree {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function clone<T>(v: T): T {
  return JSON.parse(JSON.stringify(v)) as T;
}

function getIn(tree: unknown, path: Path): unknown {
  return path.reduce<unknown>((node, key) => (isObj(node) ? node[key] : undefined), tree);
}

function setIn(tree: Tree, path: Path, value: unknown): Tree {
  const [head, ...rest] = path;
  const copy: Tree = { ...tree };
  copy[head] = rest.length ? setIn((isObj(tree[head]) ? tree[head] : {}) as Tree, rest, value) : value;
  return copy;
}

/** A typed draft leaf back to its JSON value (number fields are edited as text). */
function normalize(draft: unknown, original: unknown): unknown {
  if (typeof original === 'number' || (original === null && typeof draft === 'string')) {
    if (typeof draft === 'string') {
      const t = draft.trim();
      if (t === '' && original === null) return null;
      const n = Number(t.replace(',', '.'));
      return t !== '' && Number.isFinite(n) ? n : draft;
    }
  }
  return draft;
}

/** Changed leaves of `draft` against `base` (lists compared whole). */
function diff(base: unknown, draft: unknown): unknown {
  if (isObj(base) && isObj(draft)) {
    const out: Tree = {};
    for (const key of Object.keys(draft)) {
      const d = diff(base[key], draft[key]);
      if (d !== undefined) out[key] = d;
    }
    return Object.keys(out).length ? out : undefined;
  }
  const value = normalize(draft, base);
  return JSON.stringify(value) === JSON.stringify(base) ? undefined : value;
}

function lines(value: unknown): string {
  return Array.isArray(value) ? value.join('\n') : '';
}

function toList(text: string): string[] {
  return text.split(/[\n,]/).map(s => s.trim()).filter(Boolean);
}

// ── Generic field renderer (thresholds, score) ───────────────────────────

function Field({
  path,
  value,
  def,
  disabled,
  onChange,
}: {
  path: Path;
  value: unknown;
  def: unknown;
  disabled: boolean;
  onChange: (path: Path, value: unknown) => void;
}) {
  const key = path[path.length - 1];
  const label = FIELD_LABEL[key] ?? key;
  if (isObj(def)) {
    return (
      <fieldset className="diag-fieldset">
        <legend>{label}</legend>
        {Object.keys(def).map(k => (
          <Field
            key={k}
            path={[...path, k]}
            value={isObj(value) ? value[k] : undefined}
            def={def[k]}
            disabled={disabled}
            onChange={onChange}
          />
        ))}
      </fieldset>
    );
  }
  const changed = JSON.stringify(normalize(value, def)) !== JSON.stringify(def);
  let input: React.ReactNode;
  if (FIXED_KEYS.has(key) || typeof def === 'boolean') {
    input = <span className="diag-field__fixed">{key === 'mode' ? MODE_LABEL[String(value)] ?? String(value) : value ? 'ja' : 'nein'}</span>;
  } else if (SEVERITY_KEYS.has(key)) {
    input = (
      <select value={String(value ?? '')} disabled={disabled} onChange={e => onChange(path, e.target.value)}>
        {(['info', 'warning', 'critical'] as const).map(s => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
      </select>
    );
  } else if (Array.isArray(def)) {
    input = (
      <input
        value={Array.isArray(value) ? value.join(', ') : String(value ?? '')}
        disabled={disabled}
        onChange={e => onChange(path, toList(e.target.value))}
      />
    );
  } else {
    input = (
      <input
        inputMode="decimal"
        value={value == null ? '' : String(value)}
        disabled={disabled}
        onChange={e => onChange(path, e.target.value)}
      />
    );
  }
  return (
    <label className={`diag-field${changed ? ' diag-field--changed' : ''}`}>
      <span className="diag-field__label">{label}</span>
      {input}
      {!FIXED_KEYS.has(key) && typeof def !== 'boolean' && (
        <span className="diag-field__def">Standard: {Array.isArray(def) ? def.join(', ') || '–' : def == null ? '–' : SEVERITY_KEYS.has(key) ? SEVERITY_LABEL[def as 'info'] ?? String(def) : String(def)}</span>
      )}
    </label>
  );
}

// ── View ──────────────────────────────────────────────────────────────────

export function IntelSettingsView({ api, onSaved }: { api: IntelApi; onSaved: () => void }) {
  const [resp, setResp] = useState<IntelSettingsResponse | null>(null);
  const [draft, setDraft] = useState<Tree | null>(null);
  const [errors, setErrors] = useState<string[]>([]);
  const [note, setNote] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [ruleFilter, setRuleFilter] = useState('');

  useEffect(() => {
    let alive = true;
    api.settings().then(
      r => { if (alive) { setResp(r); setDraft(clone(r.settings)); } },
      e => { if (alive) setErrors([errorMessage(e)]); },
    );
    return () => { alive = false; };
  }, [api]);

  const patch = useMemo(() => (resp && draft ? diff(resp.settings, draft) : undefined), [resp, draft]);

  if (!resp || !draft) {
    return errors.length ? <div className="diag-error">{errors.join(' · ')}</div> : <div className="view-empty">Lade Einstellungen…</div>;
  }
  const canEdit = resp.can_edit;
  const change = (path: Path, value: unknown) => setDraft(d => (d ? setIn(d, path, value) : d));

  const send = async (body: Record<string, unknown>) => {
    setBusy(true);
    setNote(null);
    try {
      const next = await api.saveSettings(body);
      setResp(next);
      setDraft(clone(next.settings));
      setErrors([]);
      setNote('Gespeichert.');
      onSaved();
    } catch (e) {
      const text = errorMessage(e).replace(/^HTTP 400: /, '');
      setErrors(text.split('; '));
    } finally {
      setBusy(false);
    }
  };

  const defaults = resp.defaults;
  const thresholds = (draft.thresholds ?? {}) as Tree;
  const defThresholds = (defaults.thresholds ?? {}) as Tree;
  const exclusions = (draft.exclusions ?? {}) as Tree;
  const fleetUntil = getIn(resp.settings, ['maintenance', 'fleet_until']);
  const now = Date.now() / 1000;
  const fleetActive = typeof fleetUntil === 'number' && fleetUntil > now;
  const types = Object.keys(defThresholds).filter(t => !RULE_META.has(t));
  const excludedTypes = new Set((exclusions.incident_types as string[] | undefined) ?? []);
  const excludedRouters = new Set((exclusions.routers as string[] | undefined) ?? []);
  const rules = types.filter(t =>
    !ruleFilter || t.includes(ruleFilter.toLowerCase()) || typeLabel(t).toLowerCase().includes(ruleFilter.toLowerCase()),
  );

  const toggleIn = (key: 'incident_types' | 'routers', id: string, on: boolean) => {
    const current = new Set((exclusions[key] as string[] | undefined) ?? []);
    if (on) current.add(id); else current.delete(id);
    change(['exclusions', key], Array.from(current));
  };

  return (
    <div className="diag-settings">
      {!canEdit && (
        <div className="settings-info">Nur Administratoren können die Einstellungen ändern.</div>
      )}
      {errors.length > 0 && (
        <div className="diag-error">
          {errors.map((e, i) => <div key={i}>{e}</div>)}
        </div>
      )}
      {note && <div className="diag-ok">{note}</div>}

      <div className="settings-card">
        <div className="settings-card__heading">Wartung</div>
        <div className="settings-row">
          <span className="settings-row__label">Ganze Flotte</span>
          <span className="settings-row__value">
            {fleetActive ? `aktiv bis ${formatTs(fleetUntil as number)}` : 'aus'}
          </span>
        </div>
        {canEdit && (
          <div className="diag-actions">
            {[1, 4, 24].map(h => (
              <button
                key={h}
                type="button"
                className="diag-btn"
                disabled={busy}
                onClick={() => send({ maintenance: { fleet_until: Math.floor(now + h * 3600) } })}
              >
                {h} h Wartung
              </button>
            ))}
            {fleetActive && (
              <button type="button" className="diag-btn" disabled={busy} onClick={() => send({ maintenance: { fleet_until: null } })}>
                Wartung beenden
              </button>
            )}
          </div>
        )}
        {resp.routers.map(r => (
          <div key={r.id} className="settings-row">
            <span className="settings-row__label">{r.name}</span>
            <span className="settings-row__value">{r.maintenance ? 'Wartung' : 'normal'}</span>
          </div>
        ))}
        <div className="settings-info">
          Während der Wartung werden Ereignisse markiert gespeichert, aber keine Incidents geöffnet.
          Einzelne Router schaltet der Schalter „Wartungsmodus“ des Routers in Home Assistant.
        </div>
      </div>

      <div className="settings-card">
        <div className="settings-card__heading">Allgemein</div>
        <Field path={['notify_min_severity']} value={draft.notify_min_severity} def={defaults.notify_min_severity} disabled={!canEdit} onChange={change} />
        <Field path={['retention_days']} value={draft.retention_days} def={defaults.retention_days} disabled={!canEdit} onChange={change} />
        <Field path={['max_events']} value={draft.max_events} def={defaults.max_events} disabled={!canEdit} onChange={change} />
        <div className="settings-info">
          HA-Ereignis ab Schweregrad · Aufbewahrung in Tagen (max. 365) · gespeicherte Ereignisse (max. 10 000).
        </div>
      </div>

      <div className="settings-card">
        <div className="settings-card__heading">Ausnahmen</div>
        <label className="diag-field diag-field--block">
          <span className="diag-field__label">MAC-Adressen (eine je Zeile)</span>
          <textarea
            rows={3}
            value={lines(exclusions.macs)}
            disabled={!canEdit}
            spellCheck={false}
            onChange={e => change(['exclusions', 'macs'], toList(e.target.value))}
          />
        </label>
        <label className="diag-field diag-field--block">
          <span className="diag-field__label">SSIDs (eine je Zeile)</span>
          <textarea
            rows={2}
            value={lines(exclusions.ssids)}
            disabled={!canEdit}
            onChange={e => change(['exclusions', 'ssids'], e.target.value.split('\n').map(s => s.trim()).filter(Boolean))}
          />
        </label>
        <div className="diag-field__label">Router ohne Score</div>
        <div className="diag-checks">
          {resp.routers.map(r => (
            <label key={r.id} className="diag-check">
              <input type="checkbox" disabled={!canEdit} checked={excludedRouters.has(r.id)} onChange={e => toggleIn('routers', r.id, e.target.checked)} />
              {r.name}
            </label>
          ))}
        </div>
        <div className="diag-field__label">Incident-Typen ausblenden</div>
        <div className="diag-checks">
          {types.map(t => (
            <label key={t} className="diag-check">
              <input type="checkbox" disabled={!canEdit} checked={excludedTypes.has(t)} onChange={e => toggleIn('incident_types', t, e.target.checked)} />
              {typeLabel(t)}
            </label>
          ))}
        </div>
      </div>

      <div className="settings-card">
        <div className="settings-card__heading">Schwellen</div>
        <input
          className="diag-search"
          placeholder="Regel suchen…"
          value={ruleFilter}
          onChange={e => setRuleFilter(e.target.value)}
        />
        {rules.map(t => {
          const changed = diff(defThresholds[t], thresholds[t]) !== undefined;
          return (
            <details key={t} className="diag-rule">
              <summary>
                {typeLabel(t)} <span className="diag-mono diag-muted">{t}</span>
                {changed && <span className="diag-pill diag-pill--info">angepasst</span>}
              </summary>
              <div className="diag-rule__fields">
                {Object.keys(defThresholds[t] as Tree).map(k => (
                  <Field
                    key={k}
                    path={['thresholds', t, k]}
                    value={(thresholds[t] as Tree | undefined)?.[k]}
                    def={(defThresholds[t] as Tree)[k]}
                    disabled={!canEdit}
                    onChange={change}
                  />
                ))}
                {canEdit && changed && (
                  <button type="button" className="diag-btn" onClick={() => change(['thresholds', t], clone(defThresholds[t]))}>
                    Auf Standard zurücksetzen
                  </button>
                )}
              </div>
            </details>
          );
        })}
        <details className="diag-rule">
          <summary>Allgemeine Fristen</summary>
          <div className="diag-rule__fields">
            {Array.from(RULE_META).map(t => (
              <Field key={t} path={['thresholds', t]} value={thresholds[t]} def={defThresholds[t]} disabled={!canEdit} onChange={change} />
            ))}
          </div>
        </details>
        <details className="diag-rule">
          <summary>Health-Score</summary>
          <div className="diag-rule__fields">
            <Field path={['score']} value={draft.score} def={defaults.score} disabled={!canEdit} onChange={change} />
          </div>
        </details>
      </div>

      {canEdit && (
        <div className="diag-savebar">
          <button
            type="button"
            className="diag-btn diag-btn--primary"
            disabled={busy || patch === undefined}
            onClick={() => patch !== undefined && send(patch as Record<string, unknown>)}
          >
            Speichern
          </button>
          <button type="button" className="diag-btn" disabled={busy || patch === undefined} onClick={() => setDraft(clone(resp.settings))}>
            Verwerfen
          </button>
          <span className="settings-info">{patch === undefined ? 'Keine Änderungen.' : 'Ungespeicherte Änderungen.'}</span>
        </div>
      )}
    </div>
  );
}
