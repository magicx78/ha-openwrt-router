import React from 'react';
import { TopologyView } from './TopologyView';
import { MOCK_DATA } from './mockData';

/**
 * App — entry point for the standalone dev mode.
 *
 * In production (Home Assistant panel) TopologyView is mounted directly
 * inside the custom element, optionally receiving live data from the
 * /api/openwrt_topology/snapshot endpoint instead of MOCK_DATA.
 */
export function App() {
  return <TopologyView data={MOCK_DATA} />;
}
