/**
 * StabilityView — "Stabilität" sub-tab of the Diagnose view (B6).
 *
 * Client table (worst first, filters, sort, search, paging; cards on a
 * phone), client detail, historical AP comparison and the settings of the
 * client stability engine. Data from /api/openwrt_topology/intelligence/
 * clients* (engine memory, no router calls). Loads on open and on a change
 * of filter or window; the panel's 30 s refresh reloads at most every 60 s.
 *
 * 1.43: sort by AP, 7-day availability and trend; the last problem includes
 * failed authentication, association and DHCP; more AP figures; score
 * weights and class limits editable here (admin only).
 */

import React, { useCallback, useEffect, useRef, useState } from 'react';
import type { IntelApi, IntelQuery } from '../api';
import type {
  StabilityApView,
  StabilityRow,
  StabilitySettingsResponse,
  StabilityTable,
  StabilityWindow,
} from '../types';
import { errorMessage, formatTs } from '../utils/intel';
import {
  CLASS_LABEL,
  PART_LABEL,
  STATE_LABEL,
  bandLabel,
  kindText,
  pct,
  problemText,
  recommendationText,
} from '../utils/stability';
import { ClientStabilityDetail, Score } from './ClientStabilityDetail';

type Section = 'clients' | 'aps' | 'settings';

const SORTS: Array<{ id: string; label: string }> = [
  { id: 'score', label: 'Score (schlechteste zuerst)' },
  { id: '-score', label: 'Score (beste zuerst)' },
  { id: 'availability', label: 'Verfügbarkeit 24 h (schlechteste zuerst)' },
  { id: '-availability', label: 'Verfügbarkeit 24 h (beste zuerst)' },
  { id: 'availability_7d', label: 'Verfügbarkeit 7 Tage (schlechteste zuerst)' },
  { id: 'trend', label: 'Trend (stärkster Abfall zuerst)' },
  { id: '-reconnects', label: 'Reconnects' },
  { id: '-last_problem', label: 'Letztes Problem' },
  { id: '-last_disconnect', label: 'Letzter Abbruch' },
  { id: 'coverage', label: 'Messabdeckung' },
  { id: 'router', label: 'Access Point (A–Z)' },
  { id: '-router', label: 'Access Point (Z–A)' },
  { id: 'name', label: 'Name' },
];
const PAGE = 100;
const MIN_RELOAD_MS = 60_000;
const TREND = { up: '↑', down: '↓', flat: '→' } as const;

interface Props {
  api: IntelApi;
  refreshKey: string;
  routers: Array<{ id: string; name: string }>;
  onOpenIncident: (id: string) => void;
}

/** Counter that moves on the panel refresh, but at most every 60 s. */
function useThrottledTick(refreshKey: string): number {
  const [tick, setTick] = useState(0);
  const last = useRef(Date.now());
  useEffect(() => {
    if (Date.now() - last.current < MIN_RELOAD_MS) return;
    last.current = Date.now();
    setTick(t => t + 1);
  }, [refreshKey]);
  return tick;
}

function useDebounced(value: string, ms: number): string {
  const [out, setOut] = useState(value);
  useEffect(() => {
    const id = setTimeout(() => setOut(value), ms);
    return () => clearTimeout(id);
  }, [value, ms]);
  return out;
}

function Row({ row, onOpen }: { row: StabilityRow; onOpen: () => void }) {
  return (
    <button type="button" className="stab-row" onClick={onOpen}>
      <span className="stab-row__name">
        <span className="diag-table__name">{row.name ?? row.mac}</span>
        <span className="diag-mono diag-table__meta">{row.name ? row.mac : row.ip ?? ''}</span>
      </span>
      <span className="stab-row__where diag-table__meta">
        {row.router_name ?? '–'} · {bandLabel(row.band)}{row.ssid ? ` · ${row.ssid}` : ''}
      </span>
      <span className={`stab-state stab-state--${row.state}`}>{STATE_LABEL[row.state] ?? row.state}</span>
      <span className="stab-row__score">
        <Score score={row.score} />
        {row.trend && <span className={`stab-trend stab-trend--${row.trend}`} title="gegenüber den 24 h davor">{TREND[row.trend]}</span>}
        <span className="diag-table__meta">{CLASS_LABEL[row.class]}</span>
      </span>
      <span className="stab-row__num" title="Verfügbarkeit 24 h / 7 Tage">
        {pct(row.availability_24h)} / {pct(row.availability_7d)}
      </span>
      <span className="stab-row__num" title="Reconnects 24 h">
        {row.reconnects_24h ?? '–'} <span className="diag-table__meta">Reconn.</span>
      </span>
      <span className="stab-row__num diag-table__meta" title="Letztes Problem (Abbruch oder fehlgeschlagene Anmeldung, Assoziierung, DHCP)">
        {row.last_problem
          ? `${formatTs(row.last_problem.ts)} · ${problemText(row.last_problem)}`
          : row.last_disconnect ? formatTs(row.last_disconnect.ts) : 'kein Problem'}
      </span>
      <span className="stab-row__num diag-table__meta" title="Messabdeckung 24 h">{pct(row.coverage)} Daten</span>
    </button>
  );
}

function ClientTable({
  api,
  tick,
  onOpen,
}: {
  api: IntelApi;
  tick: number;
  onOpen: (mac: string) => void;
}) {
  const [filters, setFilters] = useState<Record<string, string>>({ sort: 'score' });
  const [search, setSearch] = useState('');
  const q = useDebounced(search.trim(), 400);
  const [table, setTable] = useState<StabilityTable | null>(null);
  const [rows, setRows] = useState<StabilityRow[]>([]);
  const [error, setError] = useState<string | null>(null);
  const query: IntelQuery = { ...filters, q: q || undefined, limit: PAGE };

  useEffect(() => {
    let alive = true;
    api.clients(query).then(
      t => { if (alive) { setTable(t); setRows(t.clients); setError(null); } },
      e => { if (alive) setError(errorMessage(e)); },
    );
    return () => { alive = false; };
    // `query` is rebuilt from filters and q on every render
  }, [api, filters, q, tick]);

  const more = async () => {
    if (!table?.next_cursor) return;
    try {
      const page = await api.clients({ ...query, cursor: table.next_cursor });
      setTable(page);
      setRows(prev => [...prev, ...page.clients]);
    } catch (e) {
      setError(errorMessage(e));
    }
  };

  const set = (key: string) => (e: React.ChangeEvent<HTMLSelectElement>) =>
    setFilters(prev => ({ ...prev, [key]: e.target.value }));

  return (
    <>
      <div className="diag-filters">
        <label>
          Suche
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="Name, MAC, IP" spellCheck={false} maxLength={64} />
        </label>
        <label>
          Access Point
          <select value={filters.router ?? ''} onChange={set('router')}>
            <option value="">Alle</option>
            {(table?.routers ?? []).map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
          </select>
        </label>
        <label>
          Band
          <select value={filters.band ?? ''} onChange={set('band')}>
            <option value="">Alle</option>
            {['2.4g', '5g', '6g'].map(b => <option key={b} value={b}>{bandLabel(b)}</option>)}
          </select>
        </label>
        <label>
          SSID
          <select value={filters.ssid ?? ''} onChange={set('ssid')}>
            <option value="">Alle</option>
            {(table?.ssids ?? []).map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </label>
        <label>
          Klasse
          <select value={filters.class ?? ''} onChange={set('class')}>
            <option value="">Alle</option>
            {Object.entries(CLASS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </label>
        <label>
          Zustand
          <select value={filters.state ?? ''} onChange={set('state')}>
            <option value="">Alle</option>
            {Object.entries(STATE_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </label>
        <label>
          Sortierung
          <select value={filters.sort} onChange={set('sort')}>
            {SORTS.map(s => <option key={s.id} value={s.id}>{s.label}</option>)}
          </select>
        </label>
      </div>
      {error && <div className="diag-error">{error}</div>}
      {table && !table.enabled && (
        <div className="settings-info">Die Client-Stabilität ist ausgeschaltet; es werden keine neuen Daten gesammelt.</div>
      )}
      {table && (
        <div className="settings-info">
          {table.total} WLAN-Clients. Kabelclients erscheinen hier nicht (keine Verbindungsdaten pro Gerät).
        </div>
      )}
      {table && rows.length === 0 && !error && <div className="view-empty">Keine Clients für diese Filter.</div>}
      <div className="stab-rows">
        {rows.map(r => <Row key={r.mac} row={r} onOpen={() => onOpen(r.mac)} />)}
      </div>
      {table?.next_cursor && (
        <button type="button" className="diag-btn diag-btn--wide" onClick={more}>Weitere laden</button>
      )}
    </>
  );
}

function ApComparison({ api, tick, nameOf }: { api: IntelApi; tick: number; nameOf: (id: string) => string }) {
  const [win, setWin] = useState<StabilityWindow>('7d');
  const [view, setView] = useState<StabilityApView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api.clientAps(win).then(
      v => { if (alive) { setView(v); setError(null); } },
      e => { if (alive) setError(errorMessage(e)); },
    );
    return () => { alive = false; };
  }, [api, win, tick]);

  return (
    <>
      <div className="diag-filters">
        <label>
          Zeitraum
          <select value={win} onChange={e => setWin(e.target.value as StabilityWindow)}>
            <option value="24h">24 Stunden</option>
            <option value="7d">7 Tage</option>
            <option value="30d">30 Tage</option>
          </select>
        </label>
      </div>
      {error && <div className="diag-error">{error}</div>}
      {view && view.aps.length === 0 && <div className="view-empty">Noch keine AP-Daten.</div>}
      {view && view.aps.length > 0 && (
        <div className="settings-card">
          <div className="settings-card__heading">Access Points (Raten je 100 Client-Stunden)</div>
          <div className="diag-table">
            {view.aps.map(a => (
              <div key={a.ap} className="diag-table__row stab-ap">
                <span className="diag-table__name">{a.rank != null ? `${a.rank}. ` : ''}{a.name}</span>
                <span><Score score={a.stability} /></span>
                <span className="diag-table__meta">
                  {a.clients} Clients · {Math.round(a.client_hours)} h
                  {a.disconnects_per_100h != null ? ` · ${a.disconnects_per_100h} Abbrüche` : ''}
                  {a.reconnects_per_100h != null ? ` · ${a.reconnects_per_100h} Reconnects` : ''}
                  {a.flaps_per_100h != null ? ` · ${a.flaps_per_100h} Flattern` : ''}
                  {a.auth_fail_per_100h != null ? ` · ${a.auth_fail_per_100h} Anmeldefehler` : ''}
                  {a.roams_in_per_100h != null ? ` · Roaming ${a.roams_in_per_100h} rein / ${a.roams_out_per_100h ?? '–'} raus` : ''}
                  {a.rssi_mean != null ? ` · Ø ${a.rssi_mean} dBm` : ''}
                  {a.weak_share != null ? ` · ${pct(a.weak_share)} schwaches Signal` : ''}
                  {a.infra_disconnects ? ` · ${a.infra_disconnects} durch Infrastruktur` : ''}
                  {a.infra_clients ? ` (${a.infra_clients} Clients)` : ''}
                </span>
                <span className="diag-table__meta">
                  {a.status === 'insufficient' ? 'zu wenig Daten' : a.low_basis ? 'schmale Basis' : ''}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}
      {view && view.recommendations.length > 0 && (
        <div className="settings-card">
          <div className="settings-card__heading">Empfehlungen</div>
          {view.recommendations.map(r => (
            <div key={`${r.subject}-${r.key}`} className="diag-rec">
              {nameOf(r.subject)}: {recommendationText(r, nameOf)} <span className="diag-table__meta">({kindText(r)})</span>
            </div>
          ))}
        </div>
      )}
    </>
  );
}

/** Client-side check of weights and class limits (the server checks again). */
function scoreSettingsProblem(weights: Record<string, number>, classes: number[]): string | null {
  const values = Object.values(weights);
  if (values.some(v => !Number.isFinite(v) || v < 0 || v > 100)) return 'Gewichte müssen zwischen 0 und 100 liegen.';
  if (!values.some(v => v > 0)) return 'Mindestens ein Gewicht muss über 0 liegen.';
  if (classes.some(v => !Number.isFinite(v) || v < 0 || v > 100)) return 'Klassengrenzen müssen zwischen 0 und 100 liegen.';
  if (classes.some((v, i) => i > 0 && v >= classes[i - 1])) return 'Klassengrenzen müssen streng absteigen.';
  return null;
}

/** Weights of the score parts and the lower limits of the classes. */
function ScoreSettings({
  data,
  weights,
  classes,
  readOnly,
  onChange,
}: {
  data: StabilitySettingsResponse;
  weights: Record<string, number>;
  classes: number[];
  readOnly: boolean;
  onChange: (patch: Record<string, unknown>) => void;
}) {
  const parts = data.limits.parts ?? Object.keys(weights);
  const names = (data.limits.classes ?? Object.keys(CLASS_LABEL)) as Array<keyof typeof CLASS_LABEL>;
  const num = (value: string) => (value === '' ? Number.NaN : Number(value));
  return (
    <>
      <div className="settings-card__heading">Score-Gewichte (0–100)</div>
      <div className="stab-score-grid">
        {parts.map(p => (
          <label key={p} className="diag-field">
            <span className="diag-field__label">{PART_LABEL[p] ?? p}</span>
            <input type="number" min={0} max={100} step={1} disabled={readOnly}
              value={Number.isFinite(weights[p]) ? weights[p] : ''}
              onChange={e => onChange({ weights: { ...weights, [p]: num(e.target.value) } })} />
          </label>
        ))}
      </div>
      <div className="settings-card__heading">Klassengrenzen (Score ab …)</div>
      <div className="stab-score-grid">
        {classes.map((v, i) => (
          <label key={names[i] ?? i} className="diag-field">
            <span className="diag-field__label">{CLASS_LABEL[names[i]] ?? `Klasse ${i + 1}`}</span>
            <input type="number" min={0} max={100} step={1} disabled={readOnly}
              value={Number.isFinite(v) ? v : ''}
              onChange={e => onChange({ classes: classes.map((c, k) => (k === i ? num(e.target.value) : c)) })} />
          </label>
        ))}
      </div>
      <div className="settings-info">
        Darunter: {CLASS_LABEL[names[classes.length]] ?? 'kritisch'}. Der Score ist das gewichtete Mittel der bewerteten Teile; ein Teil mit Gewicht 0 zählt nicht.
      </div>
    </>
  );
}

function Settings({
  data,
  onSave,
}: {
  data: StabilitySettingsResponse | null;
  onSave: (patch: Record<string, unknown>) => Promise<void>;
}) {
  const [draft, setDraft] = useState<Record<string, unknown>>({});
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  if (!data) return <div className="view-empty">Lade Einstellungen…</div>;
  const s = { ...data.settings, ...draft };
  const st = data.status;
  const readOnly = !data.can_edit;
  const weights = (s.weights ?? {}) as Record<string, number>;
  const classes = (s.classes ?? []) as number[];
  const problem = scoreSettingsProblem(weights, classes);
  const save = async () => {
    setBusy(true);
    try {
      await onSave(draft);
      setDraft({});
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="settings-card diag-settings">
      <label className="diag-check">
        <input type="checkbox" checked={Boolean(s.enabled)} disabled={readOnly}
          onChange={e => setDraft(d => ({ ...d, enabled: e.target.checked }))} />
        Client-Stabilität erfassen
      </label>
      <label className="diag-field">
        <span className="diag-field__label">Aufbewahrung (Tage)</span>
        <input type="number" min={1} max={data.limits.retention_days_max} value={Number(s.retention_days)} disabled={readOnly}
          onChange={e => setDraft(d => ({ ...d, retention_days: Number(e.target.value) }))} />
        <span className="diag-field__def">1–{data.limits.retention_days_max}</span>
      </label>
      <label className="diag-field">
        <span className="diag-field__label">Speichergrenze (MB)</span>
        <input type="number" min={data.limits.store_mb_min} max={data.limits.store_mb_max} value={Number(s.max_store_mb)} disabled={readOnly}
          onChange={e => setDraft(d => ({ ...d, max_store_mb: Number(e.target.value) }))} />
        <span className="diag-field__def">{data.limits.store_mb_min}–{data.limits.store_mb_max}; älteste Daten werden zuerst gekürzt</span>
      </label>
      <div className="diag-kv">
        <span>Clients: <b>{st.clients}</b></span>
        <span>Speicher: <b>{st.store_bytes_last_save != null ? `${(st.store_bytes_last_save / 1e6).toFixed(2)} MB` : '–'}</b> von {(st.store_limit_bytes / 1e6).toFixed(0)} MB</span>
        <span>Gekürzt: <b>{st.trimmed_for_size}</b></span>
        <span>Sensoren für: <b>{data.settings.entity_macs.length}</b> / {data.limits.entity_max} Clients</span>
        <span>Schlafende Geräte: <b>{data.settings.sleepy_macs.length}</b></span>
      </div>
      {st.store_load_failed && <div className="diag-error">Der gespeicherte Verlauf war unlesbar; es wird neu gesammelt.</div>}
      <ScoreSettings data={data} weights={weights} classes={classes} readOnly={readOnly}
        onChange={patch => setDraft(d => ({ ...d, ...patch }))} />
      {problem && <div className="diag-error">{problem}</div>}
      {error && <div className="diag-error">{error}</div>}
      {data.can_edit ? (
        <div className="diag-actions">
          <button type="button" className="diag-btn diag-btn--primary" disabled={busy || problem != null || Object.keys(draft).length === 0} onClick={save}>
            Speichern
          </button>
          {data.defaults && (
            <button type="button" className="diag-btn" disabled={busy}
              onClick={() => setDraft(d => ({ ...d, weights: { ...data.defaults!.weights }, classes: [...data.defaults!.classes] }))}>
              Gewichte und Grenzen zurücksetzen
            </button>
          )}
        </div>
      ) : (
        <div className="settings-info">Ändern nur als Administrator.</div>
      )}
      <div className="settings-info">
        Sensoren und „schlafendes Gerät“ werden in der Detailansicht eines Clients gesetzt.
        Zurücksetzen trägt die Standardwerte ein; erst „Speichern“ übernimmt sie.
      </div>
    </div>
  );
}

export function StabilityView({ api, refreshKey, routers, onOpenIncident }: Props) {
  const tick = useThrottledTick(refreshKey);
  const [section, setSection] = useState<Section>('clients');
  const [openMac, setOpenMac] = useState<string | null>(null);
  const [settings, setSettings] = useState<StabilitySettingsResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    api.clientSettings().then(
      s => { if (alive) { setSettings(s); setError(null); } },
      e => { if (alive) setError(errorMessage(e)); },
    );
    return () => { alive = false; };
  }, [api, tick]);

  const names = new Map(routers.map(r => [r.id, r.name]));
  const nameOf = (id: string) => names.get(id) ?? id;

  const save = useCallback(async (patch: Record<string, unknown>) => {
    setSettings(await api.saveClientSettings(patch));
  }, [api]);

  const toggle = useCallback(async (list: 'entity_macs' | 'sleepy_macs', mac: string, on: boolean) => {
    const current = (await api.clientSettings()).settings[list];
    const next = on ? [...current.filter(m => m !== mac), mac] : current.filter(m => m !== mac);
    setSettings(await api.saveClientSettings({ [list]: next }));
  }, [api]);

  if (openMac) {
    return (
      <ClientStabilityDetail
        api={api}
        mac={openMac}
        tick={tick}
        nameOf={nameOf}
        canEdit={settings?.can_edit ?? false}
        onToggle={(list, on) => toggle(list, openMac, on)}
        onClose={() => setOpenMac(null)}
        onOpenIncident={onOpenIncident}
      />
    );
  }

  return (
    <>
      <div className="stab-sections" role="group" aria-label="Bereich">
        {([['clients', 'Clients'], ['aps', 'AP-Vergleich'], ['settings', 'Einstellungen']] as const).map(([id, label]) => (
          <button key={id} type="button" className={`diag-btn${section === id ? ' diag-btn--primary' : ''}`}
            onClick={() => setSection(id)} aria-pressed={section === id}>
            {label}
          </button>
        ))}
      </div>
      {error && <div className="diag-error">{error}</div>}
      {section === 'clients' && <ClientTable api={api} tick={tick} onOpen={setOpenMac} />}
      {section === 'aps' && <ApComparison api={api} tick={tick} nameOf={nameOf} />}
      {section === 'settings' && <Settings data={settings} onSave={save} />}
    </>
  );
}
