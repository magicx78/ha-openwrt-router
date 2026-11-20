/**
 * SecurityIncident — one finding ("Hinweis"): evidence, data source,
 * limitations, linked Network Intelligence incidents and the status
 * (administrators can change it).
 *
 * The backend sends no data source per incident; it is derived from the
 * detector id (detectorSource) and the detection's limitations come from the
 * detections route. Evidence lines are indicators, not proof, and are shown
 * as plain text.
 */

import React, { useState } from 'react';
import type { IncidentStatus, SecurityApi } from './securityTypes';
import {
  ASSESSMENT_LABEL,
  CATEGORY_LABEL,
  SEVERITY_LABEL,
  SEVERITY_TONE,
  STATUS_CONFIRM,
  STATUS_HELP,
  STATUS_LABEL,
  STATUS_TONE,
  TIMELINE_KIND_LABEL,
  detectionNotes,
  detectionLabel,
  detectionTone,
  detectionTitle,
  detectorSource,
  formatRelativeTs,
  formatTs,
  isLogSource,
  label,
  shortId,
  sourceName,
  statusStep,
  type StatusEvent,
} from './securityLogic.ts';
import { ErrorBox, Fact, Notice, SectionBox, Skeleton, ToneBadge, useAction, useResource } from './securityUi';

const STATUS_ORDER: IncidentStatus[] = ['open', 'confirmed', 'resolved'];

export function SecurityIncident({ api, id, isAdmin, now, onBack, onChanged }: {
  api: SecurityApi;
  id: string;
  isAdmin: boolean;
  now: number;
  onBack: () => void;
  onChanged: () => void;
}) {
  const detail = useResource(() => api.incident(id), true, id);
  const detections = useResource(() => api.detections(), true, id);
  const action = useAction();
  // Status in two steps like the device form: a click only asks (review 3, #7).
  const [pending, setPending] = useState<IncidentStatus | null>(null);

  const setStatus = async (status: IncidentStatus) => {
    const ok = await action.run(async () => { await api.setIncidentStatus(id, status); });
    if (ok) {
      setPending(null);
      detail.reload();
      onChanged();
    }
  };

  const step = (current: string | null, ev: StatusEvent) => {
    const next = statusStep(current, pending, ev);
    if (ev.kind !== 'confirm') action.clear();
    setPending(next.pending);
    if (next.send !== null) void setStatus(next.send);
  };

  const back = (
    <button type="button" className="diag-btn diag-btn--back cfg-btn" onClick={onBack}>← Zurück</button>
  );

  if (detail.data === null) {
    return (
      <div className="cfg-stack">
        {back}
        {detail.error !== null
          ? <ErrorBox error={detail.error} onRetry={detail.reload} />
          : <Skeleton rows={4} />}
      </div>
    );
  }

  const inc = detail.data.incident;
  const det = inc.detector ? detections.data?.detections.find(d => d.id === inc.detector) ?? null : null;
  const source = detectorSource(inc.detector);
  const notes = det ? detectionNotes(det) : [];
  const device = inc.clientName ?? inc.client ?? inc.clientRef ?? (inc.hasClient ? 'Gerät (nicht zuordenbar)' : null);

  return (
    <div className="cfg-stack">
      {back}
      <div className="sec-incident__head">
        <ToneBadge tone={SEVERITY_TONE[inc.severity ?? ''] ?? 'muted'}>{label(SEVERITY_LABEL, inc.severity)}</ToneBadge>
        <ToneBadge tone={STATUS_TONE[inc.status ?? ''] ?? 'muted'}>{label(STATUS_LABEL, inc.status)}</ToneBadge>
        {inc.fromLogs && <ToneBadge tone="muted">aus Logzeilen</ToneBadge>}
        <h3 className="sec-incident__title">{inc.title ?? inc.detector ?? inc.id}</h3>
      </div>
      {detail.error !== null && <ErrorBox error={detail.error} onRetry={detail.reload} />}

      {inc.hint && <Notice tone="info">{inc.hint}</Notice>}

      <SectionBox title="Einordnung">
        <Fact name="Einschätzung">{inc.assessment ? label(ASSESSMENT_LABEL, inc.assessment) : 'unbekannt'}</Fact>
        <Fact name="Kategorie">{label(CATEGORY_LABEL, inc.category)}</Fact>
        <Fact name="Router"><span className="diag-mono">{shortId(inc.routerId)}</span></Fact>
        {device !== null && <Fact name="Gerät"><span className="diag-mono sec-ident">{device}</span></Fact>}
        <Fact name="Erstmals gesehen">{formatTs(inc.firstSeen)}</Fact>
        <Fact name="Zuletzt gesehen">{formatTs(inc.lastSeen)} ({formatRelativeTs(inc.lastSeen, now)})</Fact>
        <Fact name="Zusammengefasste Ereignisse">{inc.count ?? 'unbekannt'}</Fact>
        {inc.resolvedAt !== null && <Fact name="Erledigt">{formatTs(inc.resolvedAt)}</Fact>}
      </SectionBox>

      <SectionBox
        title="Belege"
        hint="Indikatoren, die zu diesem Hinweis geführt haben. Sie sind kein Beweis für eine Ursache. Adressen und Namen sind maskiert."
      >
        {inc.evidence.length === 0
          ? <div className="cfg-hint">Keine Belege gespeichert.</div>
          : <ul className="sec-evidence">{inc.evidence.map((e, i) => <li key={i} className="diag-mono">{e}</li>)}</ul>}
      </SectionBox>

      <SectionBox title="Datenquelle und Einschränkungen">
        <Fact name="Datenquelle">
          {source ? sourceName(source) : 'unbekannt'}
        </Fact>
        {(inc.fromLogs || isLogSource(source)) && (
          <div className="cfg-hint">Die Quelle sind Logzeilen. Logzeilen können gefälscht sein, darum bleibt dieser Hinweis eine Hypothese.</div>
        )}
        {detections.data !== null && det === null && (
          <div className="cfg-hint">Zu dieser Erkennung liegen keine Verfügbarkeitsangaben vor.</div>
        )}
        {det && (
          <>
            <Fact name="Erkennung">
              {detectionTitle(det.id)} <ToneBadge tone={detectionTone(det)}>{detectionLabel(det)}</ToneBadge>
            </Fact>
            {notes.length > 0
              ? <ul className="cfg-list cfg-list--warn">{notes.map(n => <li key={n}>{n}</li>)}</ul>
              : <div className="cfg-hint">Keine Einschränkungen gemeldet.</div>}
          </>
        )}
        {detections.error !== null && detections.data === null && (
          <div className="cfg-hint">Verfügbarkeit der Erkennung konnte nicht geladen werden.</div>
        )}
      </SectionBox>

      <SectionBox
        title="Verknüpfte Vorfälle"
        hint="Zeitliche oder inhaltliche Verbindungen, keine belegte Ursache."
      >
        <div className="cfg-subtitle">Network-Intelligence-Vorfälle</div>
        {inc.linkedIncidentIds.length === 0
          ? <div className="cfg-hint">Keine verknüpft.</div>
          : <ul className="sec-evidence">{inc.linkedIncidentIds.map(l => <li key={l} className="diag-mono">{l}</li>)}</ul>}
        {inc.driftRefs.length > 0 && (
          <>
            <div className="cfg-subtitle">Konfigurationsänderungen in der Nähe</div>
            <ul className="sec-evidence">{inc.driftRefs.map(l => <li key={l} className="diag-mono">{l}</li>)}</ul>
          </>
        )}
      </SectionBox>

      <SectionBox title="Verlauf">
        {detail.data.timeline.length === 0
          ? <div className="cfg-hint">Kein Verlauf aufgezeichnet.</div>
          : (
            <ul className="sec-rows">
              {detail.data.timeline.map((t, i) => (
                <li key={`${t.ts ?? 'x'}-${i}`} className="sec-row">
                  <div className="sec-row__main">
                    <ToneBadge tone={SEVERITY_TONE[t.severity ?? ''] ?? 'muted'}>{label(SEVERITY_LABEL, t.severity)}</ToneBadge>
                    <span className="sec-row__title">{t.text ?? label(TIMELINE_KIND_LABEL, t.kind)}</span>
                  </div>
                  <div className="sec-row__meta">
                    <span>{formatTs(t.ts)}</span>
                    <span>{label(TIMELINE_KIND_LABEL, t.kind)}</span>
                  </div>
                </li>
              ))}
            </ul>
          )}
      </SectionBox>

      <SectionBox title="Status">
        {isAdmin ? (
          <>
            <div className="sec-actions" role="group" aria-label="Status ändern">
              {STATUS_ORDER.map(s => (
                <button
                  key={s}
                  type="button"
                  className={`diag-btn cfg-btn${inc.status === s ? ' diag-btn--primary' : ''}`}
                  aria-pressed={inc.status === s}
                  disabled={action.busy || inc.status === s || pending !== null}
                  onClick={() => step(inc.status, { kind: 'choose', status: s })}
                >
                  {label(STATUS_LABEL, s)}
                </button>
              ))}
            </div>
            {inc.status && STATUS_HELP[inc.status] && <div className="cfg-hint">{STATUS_HELP[inc.status]}</div>}
            {pending !== null ? (
              <form
                className="sec-edit"
                aria-label="Status ändern bestätigen"
                onSubmit={e => { e.preventDefault(); step(inc.status, { kind: 'confirm' }); }}
              >
                <div className="cfg-hint">{STATUS_CONFIRM[pending]}</div>
                <div className="sec-actions">
                  <button type="submit" className="diag-btn diag-btn--primary cfg-btn" disabled={action.busy}>
                    {action.busy ? 'Speichert…' : `„${label(STATUS_LABEL, pending)}“ setzen`}
                  </button>
                  <button type="button" className="diag-btn cfg-btn" disabled={action.busy}
                    onClick={() => step(inc.status, { kind: 'cancel' })}>
                    Abbrechen
                  </button>
                </div>
                {action.error !== null && <ErrorBox error={action.error} />}
              </form>
            ) : (
              action.error !== null && <ErrorBox error={action.error} />
            )}
          </>
        ) : (
          <div className="cfg-hint">Den Status kann nur ein Administrator ändern. Aktuell: {label(STATUS_LABEL, inc.status)}.</div>
        )}
      </SectionBox>
    </div>
  );
}
