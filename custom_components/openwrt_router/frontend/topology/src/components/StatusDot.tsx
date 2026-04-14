import React from 'react';
import { NodeStatus } from '../types';

export function StatusDot({ status }: { status: NodeStatus }) {
  return <span className={`status-dot ${status}`} />;
}

export function statusLabel(status: NodeStatus): string {
  return status === 'online' ? 'Online' : status === 'warning' ? 'Warnung' : 'Offline';
}
