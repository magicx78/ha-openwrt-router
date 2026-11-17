/**
 * ClientStabilityDetail — one client of the stability tab (B6).
 *
 * Window 1 h / 24 h / 7 d / 30 d: score with its parts, live facts,
 * timeline (online/offline/gap, disconnects as markers linking to the NI
 * incident), online share, RSSI and score history, attribution, recurring
 * patterns and recommendations. Admins can create the HA sensors of the
 * client and mark it as a sleepy device. Reads engine memory only.
 */

import React, { useEffect, useState } from 'react';
import type { IntelApi } from '../api';
import type { ClientStabilityDetail as Detail, StabilityWindow } from '../types';
import { errorMessage, formatDuration, formatTs } from '../utils/intel';
import {
  CLASS_LABEL,
  DISCONNECT_LABEL,
  PART_LABEL,
  STATE_LABEL,
  bandLabel,
  kindText,
  pct,
  recommendationText,
  scoreLevel,
} from '../utils/stability';
import { AvailabilityBars, LineChart, TimelineBar } from './StabilityCharts';
import type { Marker } from './StabilityCharts';

const WINDOWS: Array<{ id: StabilityWindow; label: string; seconds: number }> = [
  { id: '1h', label: '1 h', seconds: 3600 },
  { id: '24h', label: '24 h', seconds: 86400 },
  { id: '7d', label: '7 Tage', seconds: 7 * 86400 },
  { id: '30d', label: '30 Tage', seconds: 30 * 86400 },
];

export function Score({ score }: { score: number | null }) {
  return (
    <span className={`diag-score diag-score--${scoreLevel(score)}`} title={score == null ? 'Zu wenig Daten' : undefined}>
      {score == null ? '–' : Math.round(score)}
    </span>
  );
}

function Fact({ label, value }: { label: string; value: React.ReactNode }) {
  return (
    <div className="diag-fact">
      <span className="diag-fact__label">{label}</span>
      <span className="diag-fact__value">{value}</span>
    </div>
  );
}

interface Props {
  api: IntelApi;
  mac: string;
  tick: number;
  nameOf: (id: string) => string;
  canEdit: boolean;
  onToggle: (list: 'entity_macs' | 'sleepy_macs', on: boolean) => Promise<void>;
  onClose: () => void;
  onOpenIncident: (id: string) => void;
}

export function ClientStabilityDetail({ api, mac, tick, nameOf, canEdit, onToggle, onClose, onOpenIncident }: Props) {
  const [win, setWin] = useState<StabilityWindow>('24h');
  const [detail, setDetail] = useState<Detail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    let alive = true;
    api.client(mac, win).then(
      d => { if (alive) { setDetail(d); setError(null); } },
      e => { if (alive) setError(errorMessage(e)); },
    );
    return () => { alive = false; };
  }, [api, mac, win, tick]);

  const toggle = async (list: 'entity_macs' | 'sleepy_macs', on: boolean) => {
    setBusy(true);
    try {
      await onToggle(list, on);
      setDetail(d => d && { ...d, [list === 'entity_macs' ? 'entity' : 'sleepy']: on });
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setBusy(false);
    }
  };

  const d = detail && detail.window === win ? detail : null;
  const span = WINDOWS.find(w => w.id === win)!.seconds;
  const end = d?.now ?? Date.now() / 1000;
  const start = end - span;
  const step = win === '30d' ? 86400 : 3600;
  const markers: Marker[] = (d?.transitions ?? [])
    .filter(t => t.kind === 'end')
    .map(t => ({
      t: t.ts,
      label: `${formatTs(t.ts)} · Abbruch (${DISCONNECT_LABEL[t.class ?? ''] ?? t.reason ?? 'unbekannt'})`
        + `${t.router_name ? ` · ${t.router_name}` : ''}${t.incident_id ? ' · Vorfall öffnen' : ''}`,
      incidentId: t.incident_id,
    }));
  const rssi = win === '1h'
    ? (d?.rssi ?? []).map(p => ({ t: p.t, y: p.rssi }))
    : (d?.series ?? []).map(p => ({ t: p.t + step / 2, y: p.rssi_mean, lo: p.rssi_min, hi: p.rssi_max }));
  const live = d?.live;

  return (
    <div className="diag-detail">
      <div className="diag-detail__bar">
        <button type="button" className="diag-btn" onClick={onClose}>← Zurück</button>
        <div className="stab-windows" role="group" aria-label="Zeitraum">
          {WINDOWS.map(w => (
            <button key={w.id} type="button" className={`diag-btn${w.id === win ? ' diag-btn--primary' : ''}`}
              onClick={() => setWin(w.id)} aria-pressed={w.id === win}>
              {w.label}
            </button>
          ))}
        </div>
      </div>
      {error && <div className="diag-error">{error}</div>}
      {!d && !error && <div className="view-empty">Lade Client…</div>}
      {d && live && (
        <>
          <div className="diag-detail__head">
            <span className={`stab-state stab-state--${live.state}`}>{STATE_LABEL[live.state] ?? live.state}</span>
            <span className="diag-detail__title">{live.hostname ?? d.mac}</span>
            <span className="stab-head-score">
              <Score score={d.score.score} /> <span className="diag-table__meta">{CLASS_LABEL[d.score.class]}</span>
            </span>
          </div>

          <div className="diag-facts">
            <Fact label="MAC" value={<span className="diag-mono">{d.mac}{live.private_mac ? ' (privat)' : ''}</span>} />
            <Fact label="IP" value={live.ip ?? '–'} />
            <Fact label="Access Point" value={live.router_name ?? '–'} />
            <Fact label="Band · SSID" value={`${bandLabel(live.band)} · ${live.ssid ?? '–'}`} />
            <Fact label="Signal" value={live.rssi != null ? `${live.rssi} dBm` : '–'} />
            <Fact label="Verbunden seit" value={live.session_start ? formatTs(live.session_start) : '–'} />
            <Fact label="Zuletzt gesehen" value={formatTs(live.last_seen)} />
            <Fact label="Letzter Abbruch" value={live.last_disconnect ? formatTs(live.last_disconnect.ts) : '–'} />
            <Fact label="Verfügbarkeit" value={pct(d.stats.availability)} />
            <Fact label="Messabdeckung" value={pct(d.stats.coverage)} />
            <Fact label="Sitzungen" value={String(d.stats.sessions)} />
            <Fact label="Längste stabile Sitzung" value={d.stats.longest_stable_s ? formatDuration(d.stats.longest_stable_s) : '–'} />
            <Fact label="Reconnects" value={d.stats.log_coverage ? String(d.stats.reconnects) : 'kein Log'} />
            <Fact label="Roaming · Flattern" value={`${d.stats.roams_in} · ${d.stats.roam_flaps}`} />
            <Fact label="Anmelde-/DHCP-Fehler" value={`${d.stats.auth_fail} · ${d.stats.dhcp_fail}`} />
            <Fact label="Schwaches Signal" value={pct(d.stats.weak_share)} />
          </div>

          <div className="settings-card">
            <div className="settings-card__heading">Verlauf</div>
            {d.timeline.length > 0 ? (
              <TimelineBar segments={d.timeline} start={start} end={end} markers={markers} onOpenIncident={onOpenIncident} />
            ) : (
              <div className="settings-info">Keine Zeitleiste für 30 Tage (Verbindungswechsel werden 24 h gespeichert); der Online-Anteil je Tag steht darunter.</div>
            )}
            <div className="stab-legend">
              <span className="stab-key stab-key--online">online</span>
              <span className="stab-key stab-key--offline">offline</span>
              <span className="stab-key stab-key--gap">Messlücke</span>
              <span className="stab-key stab-key--unknown">unbekannt</span>
              <span>▲ Abbruch</span>
            </div>
            <AvailabilityBars
              points={d.series.map(p => ({
                t: p.t,
                share: p.observed_s > 0 ? Math.min(1, p.online_s / p.observed_s) : null,
                problems: p.disconnects + p.infra,
              }))}
              start={start}
              end={end}
              step={step}
            />
            <LineChart points={rssi} start={start} end={end} min={-95} max={-30} unit="dBm"
              label={win === '1h' ? 'Signal je Abfrage' : 'Signal (Mittel, Min–Max)'} />
            {d.score_series.length > 0 && (
              <LineChart points={d.score_series.map(p => ({ t: p.t, y: p.score }))} start={start} end={end}
                min={0} max={100} unit="" label={win === '30d' ? 'Score je Tag' : 'Score (gleitende 24 h)'} />
            )}
          </div>

          <div className="settings-card">
            <div className="settings-card__heading">Score-Teile (Datenbasis {pct(d.score.coverage)})</div>
            <div className="diag-table">
              {Object.entries(d.score.parts).map(([key, part]) => (
                <div key={key} className={`diag-table__row stab-part${part.included ? '' : ' stab-part--off'}`}>
                  <span className="diag-table__name">{PART_LABEL[key] ?? key}</span>
                  <span><Score score={part.value} /></span>
                  <span className="diag-table__meta">
                    {part.included ? `Abdeckung ${pct(part.coverage)}` : 'nicht bewertet (zu wenig Daten)'}
                  </span>
                </div>
              ))}
            </div>
          </div>

          <div className="settings-card">
            <div className="settings-card__heading">Ursachen (letzte 24 h)</div>
            <div className="settings-info">
              {d.attribution.total === 0
                ? 'Keine Abbrüche in den letzten 24 Stunden.'
                : `${d.attribution.infra} von ${d.attribution.total} Abbrüchen fallen in Infrastruktur-Probleme, `
                  + `${d.attribution.client} liegen beim Client oder sind ungeklärt`
                  + `${d.attribution.kind === 'hypothesis' ? ` (Hypothese, ${pct(d.attribution.confidence)})` : d.attribution.kind === 'confirmed' ? ' (bestätigt)' : ''}.`}
            </div>
            {d.incidents.length > 0 && (
              <div className="diag-kv">
                {d.incidents.map(inc => (
                  <button key={inc.incident_id} type="button" className="diag-link" onClick={() => onOpenIncident(inc.incident_id)}>
                    Vorfall {inc.cause ?? inc.incident_id}
                  </button>
                ))}
              </div>
            )}
            <div className="diag-kv">
              <span>Uhrzeit-Muster: <b>{d.patterns.time.status === 'found'
                ? d.patterns.time.hours.map(h => `${h.hour} Uhr (${h.hit_days}/${h.covered_days} Tage)`).join(', ')
                : d.patterns.time.status === 'insufficient' ? 'zu wenig Tage' : 'keins'}</b></span>
              <span>Signaltrend: <b>{d.patterns.signal.status === 'degraded'
                ? `schlechter um ${Math.abs(d.patterns.signal.delta_db ?? 0)} dB`
                : d.patterns.signal.status === 'no_trend' ? 'gleichbleibend' : 'nicht vergleichbar'}</b></span>
              <span>AP-Muster: <b>{d.patterns.ap.status === 'found' && d.patterns.ap.worst_ap
                ? `instabil an ${nameOf(d.patterns.ap.worst_ap)}`
                : d.patterns.ap.status === 'insufficient' ? 'zu wenig Daten' : 'keins'}</b></span>
            </div>
          </div>

          {d.recommendations.length > 0 && (
            <div className="settings-card">
              <div className="settings-card__heading">Empfehlungen</div>
              <div className="diag-list">
                {d.recommendations.map(r => (
                  <div key={r.key} className="diag-rec">
                    {recommendationText(r, nameOf)} <span className="diag-table__meta">({kindText(r)})</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {canEdit ? (
            <div className="diag-checks">
              <label className="diag-check">
                <input type="checkbox" checked={d.entity} disabled={busy} onChange={e => toggle('entity_macs', e.target.checked)} />
                Sensoren in Home Assistant anlegen
              </label>
              <label className="diag-check">
                <input type="checkbox" checked={d.sleepy} disabled={busy} onChange={e => toggle('sleepy_macs', e.target.checked)} />
                Schlafendes Gerät (lange Pausen sind normal)
              </label>
            </div>
          ) : (
            <div className="settings-info">Sensoren und Geräteart nur als Administrator änderbar.</div>
          )}
        </>
      )}
    </div>
  );
}
