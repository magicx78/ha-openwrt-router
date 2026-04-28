/**
 * MobileView — Compact scrollable list layout for narrow screens (< 560px).
 *
 * Replaces the canvas-based SVG layout with a simple DOM flow:
 *   Internet → Gateway card → AP card + client strip → ...
 *
 * No absolute positioning, no SVG. Naturally responsive.
 */

import React from 'react';
import { TopologyData, Gateway, AccessPoint, Client, DeviceCategory } from '../types';
import { StatusDot } from './StatusDot';
import { IconRouter, IconAP, IconGlobe, IconSmartphone, IconLaptop, IconIoT, IconGuest, IconOther } from './Icons';

interface Props {
  data: TopologyData;
  onSelectGateway: () => void;
  onSelectAP: (ap: AccessPoint) => void;
  onSelectClient: (client: Client) => void;
  clientsForAP: (apId: string) => Client[];
  selectedId: string | null;
}

function MobileCategoryIcon({ category }: { category: DeviceCategory }) {
  switch (category) {
    case 'smartphone': return <IconSmartphone size={11} />;
    case 'laptop':     return <IconLaptop size={11} />;
    case 'iot':        return <IconIoT size={11} />;
    case 'guest':      return <IconGuest size={11} />;
    default:           return <IconOther size={11} />;
  }
}

export function MobileView({
  data,
  onSelectGateway,
  onSelectAP,
  onSelectClient,
  clientsForAP,
  selectedId,
}: Props) {
  return (
    <div className="mobile-view">
      {/* ── Internet indicator ── */}
      <div className="mobile-internet">
        <div className="mobile-internet__dot">
          <IconGlobe size={18} />
        </div>
        <span className="mobile-internet__label">Internet</span>
        <div className="mobile-connector" />
      </div>

      {/* ── Gateway ── */}
      <div
        className={`mobile-card mobile-card--gateway ${selectedId === data.gateway.id ? 'selected' : ''}`}
        onClick={onSelectGateway}
      >
        <div className="mobile-card__header">
          <div className="mobile-card__icon mobile-card__icon--blue">
            <IconRouter size={16} />
          </div>
          <div className="mobile-card__info">
            <div className="mobile-card__name">{data.gateway.name}</div>
            <div className="mobile-card__sub">{data.gateway.model}</div>
          </div>
          <StatusDot status={data.gateway.status} />
        </div>
        <div className="mobile-card__meta">
          <div className="mobile-meta-row"><span>LAN</span><span>{data.gateway.ip}</span></div>
          <div className="mobile-meta-row"><span>WAN</span><span>{data.gateway.wanIp}</span></div>
          {data.gateway.uptime && (
            <div className="mobile-meta-row"><span>Uptime</span><span>{data.gateway.uptime}</span></div>
          )}
        </div>
      </div>

      {/* ── Access Points ── */}
      {data.accessPoints.map(ap => {
        const clients = clientsForAP(ap.id);
        return (
          <React.Fragment key={ap.id}>
            <div className="mobile-connector" />
            <div
              className={`mobile-card ${selectedId === ap.id ? 'selected' : ''}`}
              onClick={() => onSelectAP(ap)}
            >
              <div className="mobile-card__header">
                <div className={`mobile-card__icon mobile-card__icon--${ap.uplinkType === 'wired' ? 'blue' : 'cyan'}`}>
                  <IconAP size={16} />
                </div>
                <div className="mobile-card__info">
                  <div className="mobile-card__name">{ap.name}</div>
                  <div className="mobile-card__sub">{ap.ip}</div>
                </div>
                <StatusDot status={ap.status} />
              </div>
              <div className="mobile-card__footer">
                <span className={`ap-card__badge ${ap.uplinkType}`}>
                  {ap.uplinkType === 'wired'    ? 'Kabel'
                 : ap.uplinkType === 'repeater' ? 'WLAN Repeater'
                 :                                'Mesh?'}
                </span>
                <span className="ap-card__clients">
                  <strong>{clients.length}</strong> Clients
                </span>
              </div>
            </div>
            {clients.length > 0 && (
              <div className="mobile-client-strip">
                {clients.slice(0, 6).map(c => (
                  <div
                    key={c.id}
                    className={`client-dot ${c.status}`}
                    onClick={() => onSelectClient(c)}
                  >
                    <MobileCategoryIcon category={c.category} />
                  </div>
                ))}
                {clients.length > 6 && (
                  <span className="client-dot-overflow">+{clients.length - 6}</span>
                )}
              </div>
            )}
          </React.Fragment>
        );
      })}
    </div>
  );
}
