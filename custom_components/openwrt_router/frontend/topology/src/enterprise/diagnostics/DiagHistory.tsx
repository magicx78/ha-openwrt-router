/**
 * DiagHistory — per measurement series the windows 1h / 24h / 7d / 30d
 * (latency, jitter, loss, gaps, coverage) as a compact table. No chart
 * library. A window without data shows "k. A.", never 0.
 */

import React from 'react';
import type { DiagApi, HistorySeries, HistoryView } from './diagnosticsTypes';
import { NO_VALUE, groupByPoint, historyRows, label, moduleView, pointName } from './diagnosticsLogic.ts';
import { ErrorBox, Notice, SectionBox, Skeleton, Unknown, useResource } from './diagUi';

const WINDOW_LABEL: Record<string, string> = { '1h': '1 Std.', '24h': '24 Std.', '7d': '7 Tage', '30d': '30 Tage' };
const KIND_LABEL: Record<string, string> = { icmp: 'Ping', dns: 'DNS', tcp: 'TCP', http: 'HTTP', fact: 'Routerdaten' };

function seriesTitle(s: HistorySeries): string {
  return [s.targetId, s.kind ? label(KIND_LABEL, s.kind) : null, s.family ? s.family.replace('ipv', 'IPv') : null]
    .filter(Boolean).join(' · ');
}

function SeriesTable({ series, windows }: { series: HistorySeries; windows: string[] }) {
  const title = seriesTitle(series);
  return (
    <div className="dg-series">
      <div className="dg-series__title">{title}</div>
      <div className="dg-table-wrap">
        <table className="dg-table" aria-label={`Verlauf ${title}`}>
          <thead>
            <tr>
              <th scope="col">Zeitraum</th><th scope="col">Latenz (Mittel)</th><th scope="col">Jitter</th>
              <th scope="col">Verlust</th><th scope="col">Lücken</th><th scope="col">Abdeckung</th>
            </tr>
          </thead>
          <tbody>
            {historyRows(series, windows).map(r => (
              <tr key={r.window}>
                <th scope="row">{label(WINDOW_LABEL, r.window)}</th>
                {[r.latency, r.jitter, r.loss, r.gaps, r.coverage].map((v, i) => (
                  <td key={i}>{v === NO_VALUE ? <span className="dg-unknown" title="nicht gemessen">{v}</span> : v}</td>
                ))}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

export function DiagHistory({ api, rev }: { api: DiagApi; rev: number }) {
  const res = useResource<HistoryView>(() => api.history(), true, rev);
  const view = res.data;

  if (view === null) return res.error !== null ? <ErrorBox error={res.error} onRetry={res.reload} /> : <Skeleton rows={4} />;
  if (view.series === null) {
    const m = moduleView(view.state, view.reasons);
    return <Notice tone="info">Kein Verlauf: die Netzwerkdiagnose ist {m.label === 'Aus' ? 'ausgeschaltet' : `nicht aktiv (${m.label.toLowerCase()})`}.</Notice>;
  }
  const groups = groupByPoint(view.series);
  return (
    <div className="cfg-stack">
      {res.error !== null && <ErrorBox error={res.error} onRetry={res.reload} />}
      <SectionBox title="Verlauf je Messreihe" hint="Mittelwerte je Zeitraum. „k. A.“ heißt: in diesem Zeitraum nicht gemessen, nicht null.">
        {groups.length === 0 && <Unknown text="Noch keine Messreihen vorhanden" />}
        {groups.map((g, i) => (
          <details key={g.point} className="dg-details" open={i === 0}>
            <summary>{pointName(g.point)} ({g.series.length})</summary>
            {g.series.map(s => <SeriesTable key={`${s.targetId}|${s.kind}|${s.family}`} series={s} windows={view.windows} />)}
          </details>
        ))}
        {view.gaps !== null && view.gaps > 0 && (
          <div className="cfg-hint">Aufgezeichnete Messlücken insgesamt: {view.gaps} (zum Beispiel Neustarts).</div>
        )}
      </SectionBox>
    </div>
  );
}
