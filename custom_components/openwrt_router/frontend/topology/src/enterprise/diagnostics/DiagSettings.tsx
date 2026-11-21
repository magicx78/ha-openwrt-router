/**
 * DiagSettings — module on/off and the settings the backend accepts that are
 * safe to edit here: periodic measurement, its interval, and whether the HA
 * resolver counts as internal. Administrators only (DiagnosticsView renders
 * it for admins only).
 *
 * Only changed fields are sent. The target list, the scope lists and the DNS /
 * HTTP probe settings are shown read-only: they hold hosts or addresses, which
 * this panel never lets a user type in (they are changed outside the panel).
 */

import React, { useEffect, useState } from 'react';
import type { DiagApi, SettingsDraft, SettingsView } from './diagnosticsTypes';
import {
  INTERVAL_MAX_S, INTERVAL_MIN_S, buildSettingsUpdate, draftFromSettings, formatCount, formatWait, moduleView,
  targetReasonText,
} from './diagnosticsLogic.ts';
import { ErrorBox, Fact, Notice, SectionBox, Skeleton, ToneBadge, Unknown, useAction, useResource } from './diagUi';

export function DiagSettings({ api, rev, onChanged }: { api: DiagApi; rev: number; onChanged: () => void }) {
  const res = useResource<SettingsView>(() => api.settings(), true, rev);
  const [draft, setDraft] = useState<SettingsDraft | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);
  const action = useAction();
  const view = res.data;

  useEffect(() => {
    if (view) setDraft(draftFromSettings(view.settings));
  }, [view]);

  if (view === null || draft === null) {
    return res.error !== null ? <ErrorBox error={res.error} onRetry={res.reload} /> : <Skeleton rows={4} />;
  }

  const s = view.settings;
  const built = buildSettingsUpdate(s, draft);
  const dirty = Object.keys(built.update).length > 0;
  const module = moduleView(view.state, view.reasons);
  const patch = (p: Partial<SettingsDraft>) => { setDraft({ ...draft, ...p }); setSaved(false); setFormError(null); action.clear(); };

  const save = async () => {
    if (built.error) { setFormError(built.error); return; }
    if (!dirty) return;
    const ok = await action.run(async () => { await api.updateSettings(built.update); });
    if (ok) {
      setSaved(true);
      res.reload();
      onChanged();
    }
  };

  return (
    <div className="cfg-stack">
      {res.error !== null && <ErrorBox error={res.error} onRetry={res.reload} />}
      <form className="cfg-stack" onSubmit={e => { e.preventDefault(); void save(); }}>
        <SectionBox title="Netzwerkdiagnose">
          <label className="diag-check cfg-confirm">
            <input type="checkbox" checked={draft.enabled} disabled={action.busy}
              onChange={e => patch({ enabled: e.target.checked })} />
            <span>
              Netzwerkdiagnose einschalten. Home Assistant misst dann die bestätigten Ziele und wertet die Daten der Router aus.
              Ist sie aus, wird nichts gemessen und kein Wert berechnet.
            </span>
          </label>
          <Fact name="Zustand"><ToneBadge tone={module.tone}>{module.label}</ToneBadge>{module.reasons.length > 0 ? ` ${module.reasons.join(' · ')}` : ''}</Fact>
        </SectionBox>

        <SectionBox title="Regelmäßige Messung">
          <label className="diag-check cfg-confirm">
            <input type="checkbox" checked={draft.periodic} disabled={action.busy}
              onChange={e => patch({ periodic: e.target.checked })} />
            <span>Regelmäßig messen. Sonst misst Home Assistant nur auf Knopfdruck („Manuelle Diagnose“).</span>
          </label>
          <label className="dg-field">
            <span>Intervall in Sekunden ({INTERVAL_MIN_S} bis {INTERVAL_MAX_S})</span>
            <input type="text" inputMode="numeric" autoComplete="off" value={draft.intervalS}
              disabled={action.busy || !draft.periodic} onChange={e => patch({ intervalS: e.target.value })} />
          </label>
          <label className="diag-check cfg-confirm">
            <input type="checkbox" checked={draft.haResolverInternal} disabled={action.busy}
              onChange={e => patch({ haResolverInternal: e.target.checked })} />
            <span>Der Namensserver von Home Assistant ist ein interner (lokaler) Server.</span>
          </label>
          {view.load && (
            <div className="cfg-hint">
              Last: {view.load.roundsPerDay === null ? <Unknown /> : `etwa ${formatCount(view.load.roundsPerDay)} Runden`}
              {' und '}{view.load.packetsPerDay === null ? <Unknown /> : `etwa ${formatCount(view.load.packetsPerDay)} Pakete`} pro Tag.
              {view.load.runLimitMax !== null && view.load.runLimitWindowS !== null
                && ` Manuelle Diagnosen: höchstens ${view.load.runLimitMax} in ${formatWait(view.load.runLimitWindowS)}.`}
            </div>
          )}
        </SectionBox>

        <div className="dg-actions">
          <button type="submit" className="diag-btn diag-btn--primary cfg-btn" disabled={action.busy || !dirty}>
            {action.busy ? 'Speichert…' : 'Speichern'}
          </button>
          {saved && !dirty && <span className="dg-muted" role="status">Gespeichert.</span>}
        </div>
        {formError !== null && <Notice tone="warn">{formError}</Notice>}
        {action.error !== null && <ErrorBox error={action.error} />}
      </form>

      <SectionBox title="Weitere Einstellungen (nur Anzeige)"
        hint="Messziele und Adressbereiche enthalten Rechnernamen und Adressen. Sie werden nicht in diesem Panel bearbeitet.">
        <Fact name="Messziele">{s.targets.length === 0 ? <Unknown text="keine eingerichtet" /> : s.targets.length}</Fact>
        {view.targets.length > 0 && (
          <ul className="dg-rows">
            {view.targets.map(t => (
              <li key={t.id} className="dg-row">
                <span className="dg-row__title">{t.id}</span>
                <span className="dg-muted">{[t.kind, t.scope].filter(Boolean).join(' · ')}</span>
                <ToneBadge tone={t.usable ? 'ok' : 'muted'}>{t.usable ? 'nutzbar' : targetReasonText(t.reason)}</ToneBadge>
              </li>
            ))}
          </ul>
        )}
        <Fact name="Interne Netze">{formatCount(s.internalNetworkCount)}</Fact>
        <Fact name="Lokale Domains">{formatCount(s.localDomainCount)}</Fact>
        <Fact name="DNS-Testname">{s.dnsQueryName ?? <Unknown text="nicht gesetzt" />}</Fact>
        <Fact name="HTTP-Pfad">{s.httpPath ?? <Unknown />}</Fact>
      </SectionBox>
    </div>
  );
}
