/**
 * DiagRun — manual diagnosis (administrators only; DiagnosticsView renders it
 * for admins only). The targets come from the settings' target list and are
 * picked by ID; there is no free host / address field. Handles 409 (off /
 * busy), 422 (refused) and 429 (shows the wait time from Retry-After).
 */

import React, { useEffect, useState } from 'react';
import type { DiagApi, RunResult, SettingsView } from './diagnosticsTypes';
import {
  MAX_RUN_TARGETS, NO_VALUE, buildRunBody, errorInfo, findingView, outcomeView, rttText, runStatusView,
  targetReasonText, usableTargets,
} from './diagnosticsLogic.ts';
import { ErrorBox, Notice, SectionBox, Skeleton, Spinner, ToneBadge, Unknown, useAction, useResource } from './diagUi';

function useBlockedUntil(): [number, (ms: number) => void] {
  const [until, setUntil] = useState(0);
  const [, tick] = useState(0);
  useEffect(() => {
    const left = until - Date.now();
    if (left <= 0) return;
    const id = setTimeout(() => tick(n => n + 1), left + 50);
    return () => clearTimeout(id);
  }, [until]);
  return [until, setUntil];
}

function RunResultView({ result }: { result: RunResult }) {
  const status = runStatusView(result.status);
  const finding = findingView(result.finding);
  return (
    <SectionBox title="Ergebnis">
      <div className="dg-finding">
        <ToneBadge tone={status.tone}>{status.text}</ToneBadge>
        {result.probes !== null && <span className="dg-muted">{result.probes} Messungen</span>}
      </div>
      {result.results.length === 0 && result.refused.length === 0 && <Unknown text="Keine Messergebnisse geliefert" />}
      {result.results.length > 0 && (
        <ul className="dg-rows">
          {result.results.map((r, i) => {
            const o = outcomeView(r.outcome);
            const rtt = rttText(r);
            return (
              <li key={`${r.targetId}-${i}`} className="dg-row">
                <span className="dg-row__title">{r.targetId}</span>
                <ToneBadge tone={o.tone}>{o.text}</ToneBadge>
                <span className="dg-muted">{rtt === NO_VALUE ? <Unknown text="Zeit k. A." /> : rtt}</span>
              </li>
            );
          })}
        </ul>
      )}
      {result.refused.length > 0 && (
        <ul className="dg-rows">
          {result.refused.map(r => (
            <li key={r.id} className="dg-row">
              <span className="dg-row__title">{r.id}</span>
              <ToneBadge tone="warn">nicht gemessen: {targetReasonText(r.reason)}</ToneBadge>
            </li>
          ))}
        </ul>
      )}
      {finding && (
        <div className="dg-finding">
          <span className="dg-muted">Einschätzung von Home Assistant:</span>
          <ToneBadge tone={finding.tone}>{finding.text}</ToneBadge>
          {finding.causeText && <span className="dg-muted">Ursache: {finding.causeText}</span>}
          {finding.unmeasuredText && <span className="dg-muted">{finding.unmeasuredText}</span>}
        </div>
      )}
    </SectionBox>
  );
}

export function DiagRun({ api, rev, onDone }: { api: DiagApi; rev: number; onDone: () => void }) {
  const res = useResource<SettingsView>(() => api.settings(), true, rev);
  const [selected, setSelected] = useState<string[]>([]);
  const [formError, setFormError] = useState<string | null>(null);
  const [result, setResult] = useState<RunResult | null>(null);
  const [blockedUntil, setBlockedUntil] = useBlockedUntil();
  const action = useAction();
  const view = res.data;

  if (view === null) return res.error !== null ? <ErrorBox error={res.error} onRetry={res.reload} /> : <Skeleton rows={4} />;

  const usable = usableTargets(view.targets);
  const blocked = Date.now() < blockedUntil;
  const toggle = (id: string) => {
    setSelected(sel => (sel.includes(id) ? sel.filter(x => x !== id) : [...sel, id]));
    setFormError(null);
  };

  const start = async () => {
    const body = buildRunBody(selected, view.targets);
    if (body.error) { setFormError(body.error); return; }
    setResult(null);
    const ok = await action.run(async () => {
      try {
        setResult(await api.run(body.ids));
      } catch (e) {
        const info = errorInfo(e);
        // 429: keep the button locked for the time the server named
        if (info.kind === 'rate_limited' && info.waitSeconds !== null) setBlockedUntil(Date.now() + info.waitSeconds * 1000);
        if (info.kind === 'disabled') onDone(); // the module went off meanwhile: reload the overview
        throw e;
      }
    });
    if (ok) onDone();
  };

  return (
    <div className="cfg-stack">
      <SectionBox
        title="Manuelle Diagnose"
        hint="Home Assistant misst die gewählten, bestätigten Ziele einmal sofort. Es werden nur Ziele aus Ihrer Zielliste verwendet; freie Adressen sind nicht möglich.">
        {view.state === 'off' && <Notice tone="warn">Die Netzwerkdiagnose ist aus. Schalten Sie sie unter „Einstellungen“ ein.</Notice>}
        {view.targets.length === 0 ? (
          <Notice tone="info">Es sind noch keine Messziele eingerichtet. Ohne Ziele ist keine Diagnose möglich.</Notice>
        ) : (
          <fieldset className="dg-fieldset" disabled={action.busy}>
            <legend className="dg-sr-only">Messziele</legend>
            {view.targets.map(t => {
              const can = usable.some(u => u.id === t.id);
              return (
                <label key={t.id} className={`diag-check dg-target${can ? '' : ' dg-target--off'}`}>
                  <input type="checkbox" checked={selected.includes(t.id)} disabled={!can}
                    onChange={() => toggle(t.id)} />
                  <span>
                    <span className="dg-target__id">{t.id}</span>
                    {' '}<span className="dg-muted">{[t.kind, t.scope].filter(Boolean).join(' · ')}</span>
                    {!can && <> <ToneBadge tone="muted">{targetReasonText(t.reason)}</ToneBadge></>}
                  </span>
                </label>
              );
            })}
          </fieldset>
        )}
        <div className="dg-actions">
          <button type="button" className="diag-btn diag-btn--primary cfg-btn"
            disabled={action.busy || blocked || usable.length === 0 || selected.length === 0 || selected.length > MAX_RUN_TARGETS}
            onClick={() => void start()}>
            {action.busy ? 'Diagnose läuft…' : 'Diagnose starten'}
          </button>
          {usable.length > 0 && (
            <button type="button" className="diag-btn cfg-btn" disabled={action.busy}
              onClick={() => { setSelected(usable.slice(0, MAX_RUN_TARGETS).map(t => t.id)); setFormError(null); }}>
              Alle nutzbaren auswählen
            </button>
          )}
          {action.busy && <Spinner text="Die Messung kann einige Sekunden dauern." />}
        </div>
        {formError !== null && <Notice tone="warn">{formError}</Notice>}
        {action.error !== null && <ErrorBox error={action.error} />}
        {blocked && <div className="cfg-hint">Der Start ist bis zum Ablauf der Wartezeit gesperrt.</div>}
      </SectionBox>
      {result !== null && <RunResultView result={result} />}
    </div>
  );
}
