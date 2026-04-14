import React from 'react';
import { NodeLayout } from '../types';
import { IconGlobe } from './Icons';

interface Props {
  layout: NodeLayout;
}

export function InternetNode({ layout }: Props) {
  return (
    <div
      className="internet-node"
      style={{ left: layout.cx, top: layout.cy }}
    >
      <div className="internet-node__circle">
        <IconGlobe size={22} />
      </div>
      <span className="internet-node__label">Internet</span>
    </div>
  );
}
