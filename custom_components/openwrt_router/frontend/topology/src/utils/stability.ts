/**
 * stability.ts — German wording for the client stability tab (B6).
 *
 * The engine sends stable keys (class, state, part, recommendation key with
 * measured parameters); this file turns them into text. Router ids in the
 * recommendation parameters are shown by name via `nameOf`.
 */

import type { StabilityClass, StabilityProblem, StabilityRecommendation } from '../types';

export const CLASS_LABEL: Record<StabilityClass, string> = {
  very_stable: 'sehr stabil',
  stable: 'stabil',
  noticeable: 'auffällig',
  unstable: 'instabil',
  critical: 'kritisch',
  unknown: 'zu wenig Daten',
};

export const STATE_LABEL: Record<string, string> = {
  online: 'online',
  grace: 'kurz weg',
  offline: 'offline',
  unknown: 'unbekannt',
};

export const PART_LABEL: Record<string, string> = {
  disconnects: 'Abbrüche',
  reconnects: 'Reconnects',
  uptime: 'Sitzungsdauer',
  signal: 'Signal',
  auth: 'Anmeldung',
  roaming: 'Roaming',
  recurring: 'Wiederkehrende Muster',
};

export const DISCONNECT_LABEL: Record<string, string> = {
  error: 'Fehler',
  unknown: 'ohne Grund',
  inactivity: 'Inaktivität',
  leave: 'abgemeldet',
  infra: 'Infrastruktur',
};

const BAND_LABEL: Record<string, string> = { '2.4g': '2,4 GHz', '5g': '5 GHz', '6g': '6 GHz' };

export function bandLabel(band: string | null | undefined): string {
  return band ? BAND_LABEL[band] ?? band : '–';
}

export function pct(value: number | null | undefined): string {
  return value == null ? '–' : `${Math.round(value * 100)} %`;
}

/** CSS modifier of a score (same thresholds as the Diagnose scores). */
export function scoreLevel(score: number | null | undefined): 'good' | 'fair' | 'poor' | 'unknown' {
  if (score == null) return 'unknown';
  return score >= 80 ? 'good' : score >= 50 ? 'fair' : 'poor';
}

export function kindText(rec: StabilityRecommendation): string {
  if (rec.kind === 'confirmed') return 'bestätigt';
  if (rec.kind === 'hypothesis') {
    return `Hypothese${rec.confidence != null ? ` · ${pct(rec.confidence)}` : ''}`;
  }
  return 'Beobachtung';
}

/** Recommendation text with its measured numbers. */
export function recommendationText(
  rec: StabilityRecommendation,
  nameOf: (id: string) => string,
): string {
  const p = rec.params;
  const ap = (key: string) => (p[key] != null ? nameOf(String(p[key])) : '?');
  switch (rec.key) {
    case 'check_coverage':
      return `WLAN-Abdeckung prüfen: ${p.disconnects_24h} Abbrüche je 24 h, `
        + `${pct(Number(p.weak_share))} der Zeit schwaches Signal (Ø ${p.rssi_mean} dBm).`;
    case 'check_roaming':
      return `Roaming prüfen: ${p.roams} Wechsel zwischen ${ap('ap_a')} und ${ap('ap_b')} `
        + `in ${p.minutes} min.`;
    case 'check_device_schedule':
      return `Zeitplan des Geräts prüfen: Abbrüche gehäuft gegen ${p.hour} Uhr `
        + `(${p.hit_days} von ${p.covered_days} Tagen).`;
    case 'check_ap':
      return `${ap('worst_ap')} prüfen (Kanal, Sendeleistung): ${p.worst_rate} Abbrüche je `
        + `24 h dort, ${p.best_rate} an ${ap('best_ap')}.`;
    case 'infrastructure_cause':
      return `Ursache in der Infrastruktur: ${p.infra} Abbrüche fallen in `
        + `${p.incidents} Netzwerk-Vorfall/-Vorfälle.`;
    case 'infrastructure_disconnects':
      return `${p.infra} Abbrüche während Infrastruktur-Problemen beobachtet.`;
    case 'infrastructure_likely':
      return `Infrastruktur wahrscheinlich: ${p.clients} Clients mit zusammen `
        + `${p.reconnects} Reconnects, ohne erkannten Vorfall.`;
    default:
      return rec.key;
  }
}

// ── 1.43 ─────────────────────────────────────────────────────────────────

export const FAIL_LABEL: Record<string, string> = {
  auth_fail: 'Anmeldung fehlgeschlagen',
  assoc_fail: 'Assoziierung fehlgeschlagen',
  dhcp_fail: 'keine IP (DHCP)',
};

/** Short text of the last problem of a table row (disconnect or failure). */
export function problemText(problem: StabilityProblem): string {
  if (problem.kind === 'disconnect') {
    return `Abbruch (${DISCONNECT_LABEL[problem.class ?? ''] ?? 'unbekannt'})`;
  }
  return FAIL_LABEL[problem.kind] ?? problem.kind;
}

/** Data rate in kbit/s as Mbit/s text. */
export function rateText(kbit: number | null | undefined): string {
  return kbit == null ? '–' : `${(kbit / 1000).toLocaleString('de-DE', { maximumFractionDigits: 1 })} Mbit/s`;
}

/** Colour of an AP+band entry of the roaming strip (cycles after 8). */
const AP_COLORS = ['#3b82f6', '#a855f7', '#14b8a6', '#f97316', '#ec4899', '#eab308', '#84cc16', '#06b6d4'];

export function apColor(index: number): string {
  return AP_COLORS[index % AP_COLORS.length];
}

/** Ping-pong window of the engine (FLAP_WINDOW_S): back to the AP left within 10 min. */
export const FLAP_WINDOW_S = 600;
