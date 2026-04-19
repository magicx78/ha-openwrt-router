import React, { useMemo } from 'react';
import { TopologyData, Client } from '../types';
import { useAlerts } from '../useAlerts';

interface Props {
  data: TopologyData;
}

function formatBps(bps: number | undefined | null): string {
  if (bps == null) return '—';
  const mbps = bps / 1_000_000;
  if (mbps >= 1000) return `${(mbps / 1000).toFixed(1)} Gbps`;
  return `${mbps.toFixed(1)} Mbps`;
}

function formatBytes(bytes: number | undefined | null): string {
  if (bytes == null || bytes === 0) return '—';
  if (bytes >= 1_000_000_000) return `${(bytes / 1_000_000_000).toFixed(1)} GB`;
  if (bytes >= 1_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`;
  return `${(bytes / 1_000).toFixed(0)} KB`;
}

function classifyClient(c: Client): 'wired' | 'wifi-5' | 'wifi-24' {
  if (!c.band) return 'wired';
  if (c.band.includes('6 GHz') || c.band.includes('6GHz')) return 'wifi-5';
  if (c.band.includes('5')) return 'wifi-5';
  return 'wifi-24';
}

interface DonutProps {
  wired: number;
  wifi5: number;
  wifi24: number;
}

function DonutChart({ wired, wifi5, wifi24 }: DonutProps) {
  const total = wired + wifi5 + wifi24;
  if (total === 0) return <div className="footer-donut-empty">—</div>;

  const r = 28;
  const cx = 36;
  const cy = 36;
  const circ = 2 * Math.PI * r;

  const segments = [
    { value: wired,  color: '#3b82f6', label: 'Wired' },
    { value: wifi5,  color: '#a855f7', label: '5 GHz' },
    { value: wifi24, color: '#22c55e', label: '2.4 GHz' },
  ];

  let offset = 0;
  const arcs = segments.map(s => {
    const frac = s.value / total;
    const dash = frac * circ;
    const arc = { ...s, dasharray: `${dash} ${circ}`, dashoffset: -offset };
    offset += dash;
    return arc;
  });

  return (
    <div className="footer-donut">
      <svg width={72} height={72} viewBox="0 0 72 72">
        <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={10} />
        {arcs.map(a => (
          <circle
            key={a.label}
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke={a.color}
            strokeWidth={10}
            strokeDasharray={a.dasharray}
            strokeDashoffset={a.dashoffset}
            strokeLinecap="butt"
            transform={`rotate(-90 ${cx} ${cy})`}
          />
        ))}
        <text x={cx} y={cy + 5} textAnchor="middle" fontSize={11} fill="rgba(255,255,255,0.85)" fontWeight="600">
          {total}
        </text>
      </svg>
      <div className="footer-donut__legend">
        {arcs.map(a => (
          <div key={a.label} className="footer-donut__item">
            <span className="footer-donut__dot" style={{ background: a.color }} />
            <span>{a.label}</span>
            <span className="footer-donut__count">{a.value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function GlobalFooter({ data }: Props) {
  const alerts = useAlerts(data);
  const critCount = alerts.filter(a => a.severity === 'critical').length;
  const warnCount = alerts.filter(a => a.severity === 'warning').length;

  const hasIssues = critCount > 0 || warnCount > 0;
  const statusText = critCount > 0
    ? `${critCount} kritisch`
    : warnCount > 0
      ? `${warnCount} Warnung${warnCount > 1 ? 'en' : ''}`
      : 'Alles in Ordnung';
  const statusDot = critCount > 0 ? 'critical' : warnCount > 0 ? 'warning' : 'ok';

  const downBps = data.gateway.wanTraffic?.downstream_bps;
  const upBps = data.gateway.wanTraffic?.upstream_bps;

  const topTalkers = useMemo(() => {
    return [...data.clients]
      .filter(c => (c.rxBytes ?? 0) + (c.txBytes ?? 0) > 0)
      .sort((a, b) => ((b.rxBytes ?? 0) + (b.txBytes ?? 0)) - ((a.rxBytes ?? 0) + (a.txBytes ?? 0)))
      .slice(0, 5);
  }, [data.clients]);

  const maxBytes = topTalkers.length > 0
    ? (topTalkers[0].rxBytes ?? 0) + (topTalkers[0].txBytes ?? 0)
    : 1;

  const clientTypes = useMemo(() => {
    let wired = 0, wifi5 = 0, wifi24 = 0;
    for (const c of data.clients) {
      const t = classifyClient(c);
      if (t === 'wired') wired++;
      else if (t === 'wifi-5') wifi5++;
      else wifi24++;
    }
    return { wired, wifi5, wifi24 };
  }, [data.clients]);

  const tsLabel = data.timestamp
    ? new Date(data.timestamp).toLocaleTimeString('de-DE', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : '—';

  return (
    <div className="global-footer">
      {/* Sektion 1: Netzwerk Status */}
      <div className="footer-section footer-section--status">
        <div className="footer-section__title">NETZWERK STATUS</div>
        <div className="footer-status">
          <span className={`footer-status__dot footer-status__dot--${statusDot}`} />
          <span className={`footer-status__text ${hasIssues ? 'footer-status__text--warn' : ''}`}>
            {statusText}
          </span>
        </div>
        <div className="footer-status__sub">
          Letzte Akt. {tsLabel}
        </div>
        <div className="footer-status__sub">
          Alle Systeme {hasIssues ? 'mit Meldungen' : 'laufen normal'}
        </div>
      </div>

      {/* Sektion 2: Gesamt Traffic */}
      <div className="footer-section footer-section--traffic">
        <div className="footer-section__title">GESAMT TRAFFIC</div>
        <div className="footer-traffic__values">
          <span className="footer-traffic__down">↓ {formatBps(downBps)}</span>
          <span className="footer-traffic__up">↑ {formatBps(upBps)}</span>
        </div>
      </div>

      {/* Sektion 3: Top Talker */}
      <div className="footer-section footer-section--talkers">
        <div className="footer-section__title">TOP TALKER (LETZTE 24H)</div>
        {topTalkers.length === 0 ? (
          <div className="footer-talkers__empty">Keine Traffic-Daten</div>
        ) : (
          <ol className="footer-talkers__list">
            {topTalkers.map((c, i) => {
              const total = (c.rxBytes ?? 0) + (c.txBytes ?? 0);
              const pct = Math.round((total / maxBytes) * 100);
              return (
                <li key={c.id} className="footer-talkers__item">
                  <span className="footer-talkers__rank">{i + 1}.</span>
                  <span className="footer-talkers__name" title={c.ip}>{c.name || c.hostname || c.mac}</span>
                  <div className="footer-talkers__bar-wrap">
                    <div className="footer-talkers__bar" style={{ width: `${pct}%` }} />
                  </div>
                  <span className="footer-talkers__bytes">{formatBytes(total)}</span>
                </li>
              );
            })}
          </ol>
        )}
      </div>

      {/* Sektion 4: Clients nach Typ */}
      <div className="footer-section footer-section--clients-wrap">
        <div className="footer-section__title">CLIENTS NACH TYP</div>
        <div className="footer-clients-body">
          <DonutChart
            wired={clientTypes.wired}
            wifi5={clientTypes.wifi5}
            wifi24={clientTypes.wifi24}
          />
        </div>
      </div>
    </div>
  );
}
