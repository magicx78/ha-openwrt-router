import { useRef, useEffect } from 'react';
import { AccessPoint, Client } from './types';

const GHOST_TTL_MS = 10 * 60 * 1000; // 10 minutes

export interface GhostAP extends AccessPoint {
  isGhost: true;
  lastSeenMs: number; // Date.now() when last seen
}

export interface GhostClient extends Client {
  isGhost: true;
  lastSeenMs: number;
}

export interface GhostDevices {
  aps: GhostAP[];
  clients: GhostClient[];
}

export function useGhostDevices(
  liveAPs: AccessPoint[],
  liveClients: Client[],
  enabled: boolean,
): GhostDevices {
  const ghostAPs    = useRef<Map<string, GhostAP>>(new Map());
  const ghostClients = useRef<Map<string, GhostClient>>(new Map());

  useEffect(() => {
    if (!enabled) {
      ghostAPs.current.clear();
      ghostClients.current.clear();
      return;
    }

    const now = Date.now();
    const liveApIds    = new Set(liveAPs.map(a => a.id));
    const liveClientIds = new Set(liveClients.map(c => c.id));

    // Evict expired ghosts
    for (const [id, g] of ghostAPs.current) {
      if (now - g.lastSeenMs > GHOST_TTL_MS) ghostAPs.current.delete(id);
    }
    for (const [id, g] of ghostClients.current) {
      if (now - g.lastSeenMs > GHOST_TTL_MS) ghostClients.current.delete(id);
    }

    // Add newly disappeared devices as ghosts
    for (const [id, g] of ghostAPs.current) {
      if (liveApIds.has(id)) ghostAPs.current.delete(id); // came back online
    }
    for (const [id, g] of ghostClients.current) {
      if (liveClientIds.has(id)) ghostClients.current.delete(id);
    }

    // Record currently live devices so we can ghost them later
    // We store live snapshots each render so we can ghost them on next render when gone
    // (handled via the "previous live" approach below)
  }, [liveAPs, liveClients, enabled]);

  // Track previous live sets to detect disappearances
  const prevAPs    = useRef<Map<string, AccessPoint>>(new Map());
  const prevClients = useRef<Map<string, Client>>(new Map());

  if (enabled) {
    const now = Date.now();
    const liveApIds     = new Set(liveAPs.map(a => a.id));
    const liveClientIds = new Set(liveClients.map(c => c.id));

    // AP disappeared → create ghost
    for (const [id, ap] of prevAPs.current) {
      if (!liveApIds.has(id) && !ghostAPs.current.has(id)) {
        ghostAPs.current.set(id, { ...ap, isGhost: true, lastSeenMs: now });
      }
    }
    // Client disappeared → create ghost
    for (const [id, cl] of prevClients.current) {
      if (!liveClientIds.has(id) && !ghostClients.current.has(id)) {
        ghostClients.current.set(id, { ...cl, isGhost: true, lastSeenMs: now });
      }
    }

    // Update previous maps
    prevAPs.current = new Map(liveAPs.map(a => [a.id, a]));
    prevClients.current = new Map(liveClients.map(c => [c.id, c]));
  } else {
    prevAPs.current.clear();
    prevClients.current.clear();
  }

  if (!enabled) {
    return { aps: [], clients: [] };
  }

  return {
    aps:     [...ghostAPs.current.values()],
    clients: [...ghostClients.current.values()],
  };
}

export function formatLastSeen(lastSeenMs: number): string {
  const diffSec = Math.floor((Date.now() - lastSeenMs) / 1000);
  if (diffSec < 60)  return `vor ${diffSec}s`;
  const diffMin = Math.floor(diffSec / 60);
  if (diffMin < 60)  return `vor ${diffMin}m`;
  return `vor ${Math.floor(diffMin / 60)}h`;
}
