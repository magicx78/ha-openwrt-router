/**
 * TrafficView — WAN Traffic Sparkline + Top Talker panel.
 * Features #2 and #3 from the topology progress tracker.
 */

import React, { useMemo } from 'react';
import { TopologyData, Client, DslHistoryPoint } from '../types';
import { IconSmartphone, IconLaptop, IconIoT, IconGuest, IconOther } from './Icons';

interface Props {
  data: TopologyData;
  onHighlightClient: (clientId: string) => void;
}

// ── Sparkline ─────────────────────────────────────────────────────────────

function formatBps(bps: number): string {
  if (bps >= 1_000_000) return `${(bps / 1_000_000).toFixed(1)} Mbit/s`;
  if (bps >= 1_000)     return `${(bps / 1_000).toFixed(0)} kbit/s`;
  return `${bps} bit/s`;
}

interface SparklineProps {
  points: number[];   // values (bps)
  color: string;      // CSS color
  height: number;
  width: number;
  flip?: boolean;     // mirror vertically (for upload)
}

function Sparkline({ points, color, height, width, flip }: SparklineProps) {
  if (points.length < 2) {
    return <svg width={width} height={height} />;
  }
  const max = Math.max(...points, 1);
  const step = width / (points.length - 1);

  const coords = points.map((v, i) => {
    const x = i * step;
    const y = flip
      ? (v / max) * height
      : height - (v / max) * height;
    return `${x.toFixed(1)},${y.toFixed(1)}`;
  });

  const pathD = `M${coords.join(' L')}`;

  // Area fill path
  const firstY = flip ? 0 : height;
  const lastY  = flip ? 0 : height;
  const areaD  = `M0,${firstY} L${pathD.slice(1)} L${((points.length - 1) * step).toFixed(1)},${lastY} Z`;

  return (
    <svg width={width} height={height} style={{ display: 'block' }}>
      <defs>
        <linearGradient id={`sg-${color.replace('#', '')}`} x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity="0.3" />
          <stop offset="100%" stopColor={color} stopOpacity="0.02" />
        </linearGradient>
      </defs>
      <path d={areaD} fill={`url(#sg-${color.replace('#', '')})`} />
      <path d={pathD} fill="none" stroke={color} strokeWidth="1.5" strokeLinejoin="round" />
    </svg>
  );
}

function WanTrafficPanel({ data }: { data: TopologyData }) {
  const history = data.gateway.dslHistory ?? [];
  const currentDown = data.gateway.wanTraffic?.downstream_bps ?? 0;
  const currentUp   = data.gateway.wanTraffic?.upstream_bps   ?? 0;

  const downPoints = history.length > 1
    ? history.map((p: DslHistoryPoint) => p.dsl_down * 1000) // kbps → bps
    : [currentDown];
  const upPoints = history.length > 1
    ? history.map((p: DslHistoryPoint) => p.dsl_up * 1000)
    : [currentUp];

  const peakDown = Math.max(...downPoints, 0);
  const peakUp   = Math.max(...upPoints, 0);

  if (!currentDown && !currentUp && !history.length) {
    return (
      <div className="traffic-section">
        <div className="traffic-section__title">WAN Traffic</div>
        <div className="traffic-no-data">Keine Traffic-Daten verfügbar</div>
      </div>
    );
  }

  return (
    <div className="traffic-section">
      <div className="traffic-section__title">WAN Traffic</div>
      <div className="traffic-rates">
        <div className="traffic-rate traffic-rate--down">
          <span className="traffic-rate__arrow">↓</span>
          <span className="traffic-rate__value">{formatBps(currentDown)}</span>
          <span className="traffic-rate__label">Download</span>
        </div>
        <div className="traffic-rate traffic-rate--up">
          <span className="traffic-rate__arrow">↑</span>
          <span className="traffic-rate__value">{formatBps(currentUp)}</span>
          <span className="traffic-rate__label">Upload</span>
        </div>
      </div>

      {downPoints.length > 1 && (
        <div className="traffic-sparkline-wrap">
          <Sparkline points={downPoints} color="var(--traffic-down-color, #3b82f6)" height={40} width={240} />
          <div className="traffic-sparkline-peak">Peak ↓ {formatBps(peakDown)}</div>
          <Sparkline points={upPoints}   color="var(--traffic-up-color, #f97316)"   height={30} width={240} flip />
          <div className="traffic-sparkline-peak">Peak ↑ {formatBps(peakUp)}</div>
        </div>
      )}
    </div>
  );
}

// ── Top Talker ────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes >= 1_073_741_824) return `${(bytes / 1_073_741_824).toFixed(1)} GB`;
  if (bytes >= 1_048_576)     return `${(bytes / 1_048_576).toFixed(1)} MB`;
  if (bytes >= 1_024)         return `${(bytes / 1_024).toFixed(0)} KB`;
  return `${bytes} B`;
}

function smartName(client: Client): string {
  if (client.hostname && client.hostname !== client.mac) return client.hostname;
  if (client.manufacturer) return `${client.manufacturer} …${client.mac.slice(-5)}`;
  return client.mac;
}

function ClientCategoryIcon({ category }: { category: Client['category'] }) {
  const s = 13;
  switch (category) {
    case 'smartphone': return <IconSmartphone size={s} />;
    case 'laptop':     return <IconLaptop size={s} />;
    case 'iot':        return <IconIoT size={s} />;
    case 'guest':      return <IconGuest size={s} />;
    default:           return <IconOther size={s} />;
  }
}

function TopTalkerPanel({ data, onHighlightClient }: { data: TopologyData; onHighlightClient: (id: string) => void }) {
  const ranked = useMemo(() => {
    return [...data.clients]
      .filter(c => (c.rxBytes ?? 0) + (c.txBytes ?? 0) > 0)
      .sort((a, b) => ((b.rxBytes ?? 0) + (b.txBytes ?? 0)) - ((a.rxBytes ?? 0) + (a.txBytes ?? 0)))
      .slice(0, 10);
  }, [data.clients]);

  if (!ranked.length) {
    return (
      <div className="traffic-section">
        <div className="traffic-section__title">Top Traffic</div>
        <div className="traffic-no-data">Keine Client-Traffic-Daten verfügbar</div>
      </div>
    );
  }

  const maxTotal = (ranked[0].rxBytes ?? 0) + (ranked[0].txBytes ?? 0);

  return (
    <div className="traffic-section">
      <div className="traffic-section__title">Top Traffic</div>
      <div className="talker-list">
        {ranked.map((client) => {
          const total = (client.rxBytes ?? 0) + (client.txBytes ?? 0);
          const pct   = maxTotal > 0 ? Math.round((total / maxTotal) * 100) : 0;
          const rx    = client.rxBytes ?? 0;
          const tx    = client.txBytes ?? 0;
          return (
            <div
              key={client.id}
              className="talker-row"
              onClick={() => onHighlightClient(client.id)}
              title="Im Graph anzeigen"
            >
              <div className="talker-row__icon">
                <ClientCategoryIcon category={client.category} />
              </div>
              <div className="talker-row__info">
                <div className="talker-row__name">{smartName(client)}</div>
                <div className="talker-row__bar-wrap">
                  <div className="talker-bar">
                    <div className="talker-bar__fill" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              </div>
              <div className="talker-row__bytes">
                {rx > 0 && <span className="talker-bytes--down">↓{formatBytes(rx)}</span>}
                {tx > 0 && <span className="talker-bytes--up">↑{formatBytes(tx)}</span>}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Main component ────────────────────────────────────────────────────────

export function TrafficView({ data, onHighlightClient }: Props) {
  return (
    <div className="topo-view">
      <div className="view-header">
        <span className="view-title">Traffic</span>
      </div>
      <WanTrafficPanel data={data} />
      <div className="traffic-divider" />
      <TopTalkerPanel data={data} onHighlightClient={onHighlightClient} />
    </div>
  );
}
