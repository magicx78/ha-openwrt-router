/**
 * SecurityDetections — availability of every detection (verfügbar /
 * eingeschränkt / nicht verfügbar) with reason, missing source and the
 * "Format unbestätigt" mark where the backend reports it, plus the state of
 * the off-router log path and the data sources per router.
 *
 * A detection that is not available says nothing about the network: it is
 * blind, not clean.
 */

import React from 'react';
import type { DetectionsView, LogPathView, SecurityApi, SourceStatus } from './securityTypes';
import {
  LOG_PATH_LABEL,
  SOURCE_AVAILABILITY_LABEL,
  SOURCE_AVAILABILITY_TONE,
  detectionLabel,
  detectionNotes,
  detectionTitle,
  detectionTone,
  fleetText,
  formatRelativeTs,
  formatTs,
  label,
  rateLimitedText,
  reasonText,
  shortId,
  sourceName,
} from './securityLogic.ts';
import { ErrorBox, Fact, Notice, SectionBox, Skeleton, ToneBadge, Unknown, useResource } from './securityUi';

function SourceLine({ s, now }: { s: SourceStatus; now: number }) {
  // Fleet status of the log path: the same "von N von M Routern" as the coverage list.
  const fleet = fleetText(s.fleet);
  return (
    <li className="sec-source">
      <span className="sec-source__name">{sourceName(s.source)}</span>
      <ToneBadge tone={SOURCE_AVAILABILITY_TONE[s.availability] ?? 'muted'}>
        {SOURCE_AVAILABILITY_LABEL[s.availability] ?? 'Unbekannt'}
      </ToneBadge>
      {fleet && <span className="cfg-hint">{fleet}</span>}
      {s.reason && s.reason !== 'ok' && <span className="cfg-hint">{reasonText([s.reason])}</span>}
      {s.lastOk !== null && <span className="cfg-hint" title={formatTs(s.lastOk)}>zuletzt Daten {formatRelativeTs(s.lastOk, now)}</span>}
    </li>
  );
}

function LogPathCard({ view, now }: { view: LogPathView; now: number }) {
  const r = view.receiver;
  const limited = rateLimitedText(view.rateLimitedRouters);
  return (
    <SectionBox
      title="Log-Pfad"
      hint="Firewall- und DNS-Erkennungen brauchen Logzeilen, die die Router an Home Assistant senden. Ohne diesen Pfad sind sie nicht verfügbar."
    >
      <Fact name="Einstellung">{view.setting ? label(LOG_PATH_LABEL, view.setting) : <Unknown />}</Fact>
      {view.setting === 'syslog' && (
        <Fact name="Syslog-Empfänger">
          {r === null || r.listening === null
            ? <Unknown />
            : r.listening
              ? <>hört auf Port {r.port ?? '?'}{r.senders !== null ? `, ${r.senders} erlaubte Router` : ''}</>
              : <>hört nicht{r.reason ? `: ${reasonText([r.reason])}` : ''}</>}
        </Fact>
      )}
      {limited && <Notice tone="warn">{limited}</Notice>}
      {view.status.length > 0 && <ul className="sec-sources-list">{view.status.map(s => <SourceLine key={s.source} s={s} now={now} />)}</ul>}
    </SectionBox>
  );
}

export function SecurityDetections({ api, now, rev }: { api: SecurityApi; now: number; rev: number }) {
  const res = useResource<DetectionsView>(() => api.detections(), true, rev);
  const view = res.data;

  if (view === null) {
    return res.error !== null ? <ErrorBox error={res.error} onRetry={res.reload} /> : <Skeleton rows={5} />;
  }
  const routers = Object.entries(view.sources);

  return (
    <div className="cfg-stack">
      {res.error !== null && <ErrorBox error={res.error} onRetry={res.reload} />}
      <SectionBox
        title="Verfügbarkeit der Erkennungen"
        hint="Eine Erkennung, die nicht verfügbar ist, kann nichts melden. Das ist keine Entwarnung."
      >
        {view.detections.length === 0 && <div className="cfg-hint">Keine Erkennungen gemeldet.</div>}
        <ul className="sec-rows">
          {view.detections.map(d => {
            const notes = detectionNotes(d);
            return (
              <li key={d.id} className="sec-row">
                <div className="sec-row__main">
                  <ToneBadge tone={detectionTone(d)}>{detectionLabel(d)}</ToneBadge>
                  <span className="sec-row__title">{detectionTitle(d.id)}</span>
                  {d.formatUnconfirmed && <ToneBadge tone="warn">Format unbestätigt</ToneBadge>}
                </div>
                {d.reason.length > 0 && d.availability !== 'available' && (
                  <div className="cfg-hint">Grund: {reasonText(d.reason)}</div>
                )}
                {d.missing.length > 0 && (
                  <div className="cfg-hint">Fehlende Quelle: {d.missing.map(sourceName).join(', ')}</div>
                )}
                {notes.length > 0 && (
                  <ul className="cfg-list cfg-list--warn">{notes.map(n => <li key={n}>{n}</li>)}</ul>
                )}
              </li>
            );
          })}
        </ul>
      </SectionBox>

      <LogPathCard view={view.logPath} now={now} />

      <SectionBox title="Datenquellen je Router">
        {routers.length === 0 && (
          <Notice tone="warn">Noch kein Router mit Datenquellen bekannt. Alle Erkennungen sind deshalb nicht verfügbar.</Notice>
        )}
        {routers.map(([rid, list]) => (
          <details key={rid} className="sec-details">
            <summary><span className="diag-mono">{shortId(rid)}</span> ({list.length} Quellen)</summary>
            <ul className="sec-sources-list">{list.map(s => <SourceLine key={s.source} s={s} now={now} />)}</ul>
          </details>
        ))}
      </SectionBox>
    </div>
  );
}
