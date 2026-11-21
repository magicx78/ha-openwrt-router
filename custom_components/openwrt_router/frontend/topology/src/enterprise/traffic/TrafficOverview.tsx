/**
 * TrafficOverview — "Übersicht": WAN now and over 24 h, data quality,
 * interface load, top talkers of the last hour, open anomalies, the data
 * sources (and why one is not delivering) and the stored history.
 */

import React from 'react';
import type { InterfaceRow, Overview, RateRow, TalkerList } from './trafficTypes';
import {
  DASH, FAMILY_LABEL, OFF_HINT, UNKNOWN_RULE, clientLabel, fmtBytes, fmtCount, fmtPct, formatTs, overviewTiles,
  pointLabel, rateParts, reasonText, reasonsText, routerName, sourceStateView, statusView, talkerValue, utcDayNote,
  windowFacts,
} from './trafficLogic.ts';
import { CoverageBadge, Fact, Notice, SectionBox, ShownBadge, SourceList, Unknown, V } from './trafficUi';

export function OffNotice() {
  return <Notice tone="info"><strong>Aus.</strong> {OFF_HINT}</Notice>;
}

export function NotReadyNotice({ reasons }: { reasons: readonly string[] }) {
  const st = statusView('not_ready', reasons);
  return <Notice tone="warn"><strong>Eingeschränkt.</strong> {st.hint ?? 'Das Modul ist noch nicht bereit.'} Angezeigt wird, was bereits gemessen wurde.</Notice>;
}

function RateRowView({ r }: { r: RateRow }) {
  return (
    <li className="wifi-row">
      <span className="wifi-row__title">{routerName(r.routerId)} · {pointLabel(r)}</span>
      {rateParts(r).map(p => <span key={p.name}>{p.name} <V text={p.text} known={p.known} /></span>)}
      <CoverageBadge level={r.coverage} reasons={[r.coverageReason, r.directionReason]} />
    </li>
  );
}

function LoadRow({ r }: { r: InterfaceRow }) {
  const pct = r.utilizationPct;
  return (
    <li className="wifi-row">
      <span className="wifi-row__title">{routerName(r.routerId)} · {pointLabel(r)}</span>
      <span>Auslastung <V text={fmtPct(pct, 1)} known={pct !== null} reason={r.utilizationReason} /></span>
      <span className="wifi-muted">Link {r.linkMbps === null ? DASH : `${fmtCount(r.linkMbps)} Mbit/s`}</span>
      {pct !== null && (
        <span className={`trf-bar${pct >= 80 ? ' trf-bar--warn' : ''}`} style={{ flex: '1 1 100%' }} aria-hidden="true">
          <span className="trf-bar__fill" style={{ width: `${Math.max(0, Math.min(100, pct))}%` }} />
        </span>
      )}
    </li>
  );
}

export function TalkerPreview({ list }: { list: TalkerList }) {
  if (!list.rows.length) {
    return <Unknown text={`${DASH} ${reasonText(list.reason ?? 'no_data_for_window')}`} />;
  }
  return (
    <ol className="wifi-rows">
      {list.rows.map(r => (
        <li key={r.pointId} className="wifi-row">
          <span className="wifi-row__title">{r.rank ?? DASH}. {r.clientRef ? clientLabel(r.clientRef) : pointLabel(r)}</span>
          <span>{talkerValue(list.metric, r.value)}</span>
          <span className="wifi-muted">{routerName(r.routerId)}</span>
        </li>
      ))}
    </ol>
  );
}

export function TrafficOverview({ overview: o }: { overview: Overview }) {
  const tiles = overviewTiles(o);
  return (
    <>
      {o.status === 'not_ready' && <NotReadyNotice reasons={o.reasons} />}
      <div className="wifi-kpis">
        {tiles.map(t => (
          <div key={t.name} className="wifi-kpi">
            <span className="wifi-kpi__name">{t.name}</span>
            <span className="wifi-kpi__value">{t.known ? t.text : <Unknown text={t.text} />}</span>
            {t.sub && <span className="wifi-kpi__sub">{t.sub}</span>}
          </div>
        ))}
      </div>
      <div className="cfg-hint">{UNKNOWN_RULE}</div>

      <SectionBox title="WAN jetzt" hint="Je Router; Summen nur, wo jeder Teil gemessen ist.">
        {o.wan.length ? <ul className="wifi-rows">{o.wan.map(r => <RateRowView key={r.pointId} r={r} />)}</ul>
          : <Unknown text="— kein WAN-Messpunkt erfasst" />}
      </SectionBox>

      <SectionBox title="WAN letzte 24 Stunden" hint="Summe aus Stundenwerten der letzten 24 Stunden (rollend, kein Kalendertag).">
        {o.wan24h.length ? (
          <ul className="wifi-cards">
            {o.wan24h.map(w => (
              <li key={w.pointId} className="wifi-card">
                <div className="wifi-card__head">
                  <span className="wifi-card__title">{routerName(w.routerId)} · WAN</span>
                  <CoverageBadge level={w.coverage} />
                </div>
                {windowFacts(w).map(f => <Fact key={f.name} name={f.name}><V text={f.text} known={f.known} /></Fact>)}
                <Fact name="Zeitabdeckung">{w.timeCoverage === null ? <Unknown text={DASH} /> : fmtPct(w.timeCoverage * 100, 0)}</Fact>
                {w.reasons.length > 0 && <div className="wifi-muted">{reasonsText(w.reasons)}</div>}
              </li>
            ))}
          </ul>
        ) : <Unknown text="— kein WAN-Verlauf" />}
      </SectionBox>

      <SectionBox title="Datenqualität">
        {o.coverage ? (
          <div className="trf-grid">
            <Fact name="Messpunkte">{fmtCount(o.coverage.points)}</Fact>
            <Fact name="vollständig">{fmtCount(o.coverage.full)}</Fact>
            <Fact name="teilweise">{fmtCount(o.coverage.partial)}</Fact>
            <Fact name="geschätzt">{fmtCount(o.coverage.estimated)}</Fact>
            <Fact name="nicht verfügbar / unbekannt">{fmtCount(o.coverage.unavailable)} / {fmtCount(o.coverage.unknown)}</Fact>
          </div>
        ) : <Unknown text={DASH} />}
        {o.coverage && o.coverage.reasons.length > 0 && (
          <ul className="wifi-rows">
            {o.coverage.reasons.map(r => <li key={r.code} className="wifi-row"><span className="wifi-row__title">{reasonText(r.code)}</span><span>{fmtCount(r.count)} Messpunkte</span></li>)}
          </ul>
        )}
        {o.drops.length > 0 && (
          <div className="wifi-muted">Verworfen: {o.drops.map(d => `${reasonText(d.code)} ${fmtCount(d.count)}`).join(' · ')}</div>
        )}
      </SectionBox>

      <SectionBox title="Auslastung der Schnittstellen" hint="Nur mit bekannter Link-Geschwindigkeit; der höhere Wert von rx und tx.">
        {o.interfaces.length ? <ul className="wifi-rows">{o.interfaces.map(r => <LoadRow key={r.pointId} r={r} />)}</ul>
          : <Unknown text="— keine Schnittstelle erfasst" />}
      </SectionBox>

      <SectionBox title="Top Talkers (1 Stunde, Download)">
        {o.talkersTop ? <TalkerPreview list={o.talkersTop} /> : <Unknown text={DASH} />}
      </SectionBox>

      {o.anomalies && (
        <SectionBox title="Erkennung von Anomalien">
          <ul className="wifi-rows">
            {o.anomalies.families.map(f => (
              <li key={f.family} className="wifi-row">
                <span className="wifi-row__title">{FAMILY_LABEL[f.family] ?? f.family}</span>
                <ShownBadge shown={sourceStateView(f.state)} />
                {f.reason && <span className="wifi-muted">{reasonText(f.reason)}</span>}
              </li>
            ))}
          </ul>
        </SectionBox>
      )}

      <SectionBox title="Verknüpfte Module" hint="Woher Hinweise kommen und warum eine Quelle nichts liefert.">
        <SourceList sources={o.correlationSources} />
      </SectionBox>
      <SectionBox title="Flow-Quellen">
        <SourceList sources={o.flowSources} />
      </SectionBox>

      <SectionBox title="Router">
        {o.routers.length ? (
          <ul className="wifi-rows">
            {o.routers.map(r => (
              <li key={r.routerId} className="wifi-row">
                <span className="wifi-row__title">{routerName(r.routerId)}</span>
                <span>Schnittstellen {fmtCount(r.devices)}</span>
                <span>WLAN-Stationen {fmtCount(r.stations)}</span>
                <span>Conntrack {fmtCount(r.conntrackCount)}</span>
              </li>
            ))}
          </ul>
        ) : <Unknown text="— noch kein Router abgefragt" />}
      </SectionBox>

      {o.history && (
        <SectionBox title="Gespeicherter Verlauf">
          <Fact name="Profil">{o.history.profile === 'standard' ? 'Standard (90 Tage)' : o.history.profile === 'compact' ? 'Kompakt' : <Unknown text={DASH} />}</Fact>
          <Fact name="Feine Daten">{o.history.fineBytes === null ? <Unknown text="— noch nicht gespeichert" /> : fmtBytes(o.history.fineBytes)}</Fact>
          <Fact name="Grobe Daten">{o.history.coarseBytes === null ? <Unknown text="— noch nicht gespeichert" /> : fmtBytes(o.history.coarseBytes)}</Fact>
          <div className="cfg-hint">{utcDayNote(o.generatedAt)}</div>
        </SectionBox>
      )}
      <div className="wifi-muted">Stand {formatTs(o.generatedAt)}</div>
    </>
  );
}
