/**
 * PortDeviceStrip — Grouped wired-device icons below the port strip.
 *
 * One group per physical LAN port that has mapped devices: a tiny port
 * caption (LAN1) plus up to MAX_DOTS device dots (visual language of the
 * WiFi ClientDot, smaller). Hover shows name/IP/MAC + mapping confidence;
 * click opens the port detail panel. WAN never renders a group — the
 * backend cannot observe devices on the WAN side.
 */

import React, { useState } from 'react';
import type { PortStat, PortDevice } from '../types';
import {
  deviceLabel,
  isPhysicalPort,
  isWanPort,
  portSortKey,
  shortName,
  CONFIDENCE_LABEL,
} from './PortStrip';
import { IconIoT, IconLaptop, IconOther, IconRouter } from './Icons';

const MAX_DOTS = 4;

interface Props {
  ports: PortStat[];
  onSelectPort?: (port: PortStat) => void;
}

export function PortDeviceStrip({ ports, onSelectPort }: Props) {
  if (!ports || ports.length === 0) return null;
  const groups = ports
    .filter(
      (p) =>
        isPhysicalPort(p.name) &&
        !isWanPort(p) &&
        (p.connectedDevices?.length ?? 0) > 0,
    )
    .sort((a, b) => portSortKey(a.name) - portSortKey(b.name));
  if (groups.length === 0) return null;

  return (
    <div className="port-device-strip">
      {groups.map((p) => (
        <PortDeviceGroup key={p.name} port={p} onSelectPort={onSelectPort} />
      ))}
    </div>
  );
}

function PortDeviceGroup({
  port,
  onSelectPort,
}: {
  port: PortStat;
  onSelectPort?: (port: PortStat) => void;
}) {
  const devices = port.connectedDevices ?? [];
  const visible = devices.slice(0, MAX_DOTS);
  const overflow = (port.deviceCount ?? devices.length) - visible.length;

  return (
    <div className="port-device-group">
      <span className="port-device-group__label">{shortName(port.name)}</span>
      {visible.map((d) => (
        <PortDeviceDot
          key={d.mac || deviceLabel(d)}
          device={d}
          onClick={() => onSelectPort?.(port)}
        />
      ))}
      {overflow > 0 && (
        <span
          className="client-dot-overflow client-dot-overflow--port"
          onClick={(e) => {
            e.stopPropagation();
            onSelectPort?.(port);
          }}
        >
          +{overflow}
        </span>
      )}
    </div>
  );
}

function guessDeviceIcon(d: PortDevice) {
  if (d.isRouter) return <IconRouter size={10} />;
  const name = (d.name ?? '').toLowerCase();
  if (/(cam|nas|print|hue|shelly|tasmota|esp|iot|plug|bridge)/.test(name)) {
    return <IconIoT size={10} />;
  }
  if (/(pc|laptop|book|desktop|tower)/.test(name)) {
    return <IconLaptop size={10} />;
  }
  return <IconOther size={10} />;
}

function PortDeviceDot({
  device: d,
  onClick,
}: {
  device: PortDevice;
  onClick: () => void;
}) {
  const [showTooltip, setShowTooltip] = useState(false);

  return (
    <div
      className={`client-dot client-dot--port confidence--${d.confidence}`}
      onClick={(e) => {
        e.stopPropagation();
        onClick();
      }}
      onMouseEnter={() => setShowTooltip(true)}
      onMouseLeave={() => setShowTooltip(false)}
    >
      {guessDeviceIcon(d)}
      {showTooltip && (
        <div className="client-tooltip">
          <div className="client-tooltip__name">{deviceLabel(d)}</div>
          <div className="client-tooltip__meta">
            {[d.ip, d.mac].filter(Boolean).join(' · ')}
          </div>
          <div className="client-tooltip__meta">
            Zuordnung: {CONFIDENCE_LABEL[d.confidence] ?? d.confidence}
          </div>
        </div>
      )}
    </div>
  );
}
