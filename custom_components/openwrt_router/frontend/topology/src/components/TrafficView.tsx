/**
 * TrafficView — WAN Traffic Sparkline + Top Talker panel.
 * Features #2 and #3 from the topology progress tracker.
 */

import React, { useMemo } from 'react';
import { TopologyData, Client } from '../types';
import { IconSmartphone, IconLaptop, IconIoT, IconGuest, IconOther } from './Icons';
import { formatBitRate, formatBytes } from '../utils/format';

interface Props {
  data: TopologyData;
  onHighlightClient: (clientId: string) => void;
}

function WanTrafficPanel({ data }: { data: TopologyData }) {
  const wan = data.gateway.wanTraffic;
  const currentDown = wan?.downstream_bps ?? 0;
  const currentUp   = wan?.upstream_bps   ?? 0;

  // A measured 0 bit/s is data; only a missing measurement is "no data"
  if (wan?.downstream_bps == null && wan?.upstream_bps == null) {
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
          <span className="traffic-rate__value">{formatBitRate(currentDown)}</span>
          <span className="traffic-rate__label">Download</span>
        </div>
        <div className="traffic-rate traffic-rate--up">
          <span className="traffic-rate__arrow">↑</span>
          <span className="traffic-rate__value">{formatBitRate(currentUp)}</span>
          <span className="traffic-rate__label">Upload</span>
        </div>
      </div>
    </div>
  );
}

// ── Top Talker ────────────────────────────────────────────────────────────

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
                <div className="talker-row__name">{client.name}</div>
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
