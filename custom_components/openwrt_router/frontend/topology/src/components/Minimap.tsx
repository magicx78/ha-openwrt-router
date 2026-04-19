import React, { useCallback } from 'react';
import { NodeStatus } from '../types';

const MINIMAP_W = 160;
const MINIMAP_H = 100;

export interface MinimapNode {
  id: string;
  cx: number;
  cy: number;
  status: NodeStatus | 'online'; // internet always passes 'online'
  kind: 'internet' | 'gateway' | 'ap';
}

interface Props {
  nodes: MinimapNode[];
  canvasW: number;
  canvasH: number;
  pan: { x: number; y: number };
  zoom: number;
  containerW: number;
  containerH: number;
  onPanTo: (logicalX: number, logicalY: number) => void;
}

function dotFill(kind: string, status: string): string {
  if (kind === 'internet' || kind === 'gateway') return 'var(--accent)';
  if (status === 'offline') return 'var(--danger)';
  if (status === 'warning') return 'var(--warning)';
  return 'var(--success)';
}

export function Minimap({ nodes, canvasW, canvasH, pan, zoom, containerW, containerH, onPanTo }: Props) {
  const scaleX = canvasW > 0 ? MINIMAP_W / canvasW : 1;
  const scaleY = canvasH > 0 ? MINIMAP_H / canvasH : 1;

  // Viewport rect in logical coords (transform: translate(pan.x, pan.y) scale(zoom))
  // logical_x = (screen_x - pan.x) / zoom → for screen_x=0: -pan.x / zoom
  const vpLogX = -pan.x / zoom;
  const vpLogY = -pan.y / zoom;
  const vpLogW = containerW / zoom;
  const vpLogH = containerH / zoom;

  const vpX = vpLogX * scaleX;
  const vpY = vpLogY * scaleY;
  const vpW = Math.max(4, vpLogW * scaleX);
  const vpH = Math.max(4, vpLogH * scaleY);

  const handleClick = useCallback((e: React.MouseEvent<SVGSVGElement>) => {
    const rect = e.currentTarget.getBoundingClientRect();
    const mx = (e.clientX - rect.left) / rect.width * MINIMAP_W;
    const my = (e.clientY - rect.top) / rect.height * MINIMAP_H;
    onPanTo(mx / scaleX, my / scaleY);
  }, [onPanTo, scaleX, scaleY]);

  return (
    <div className="minimap" onPointerDown={e => e.stopPropagation()}>
      <svg
        className="minimap__svg"
        viewBox={`0 0 ${MINIMAP_W} ${MINIMAP_H}`}
        onClick={handleClick}
      >
        {nodes.map(n => (
          <circle
            key={n.id}
            cx={n.cx * scaleX}
            cy={n.cy * scaleY}
            r={n.kind === 'gateway' ? 5 : n.kind === 'internet' ? 4 : 3}
            fill={dotFill(n.kind, n.status)}
          />
        ))}
        <rect
          className="minimap__viewport"
          x={vpX}
          y={vpY}
          width={vpW}
          height={vpH}
        />
      </svg>
    </div>
  );
}
