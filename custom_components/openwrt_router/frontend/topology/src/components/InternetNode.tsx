import React from 'react';
import { IconGlobe } from './Icons';

export function InternetNode() {
  return (
    <div className="internet-node">
      <div className="internet-node__circle">
        <IconGlobe size={22} />
      </div>
      <span className="internet-node__label">Internet</span>
    </div>
  );
}
