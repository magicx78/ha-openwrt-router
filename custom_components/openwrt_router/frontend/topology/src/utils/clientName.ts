/**
 * clientName.ts — One display-name rule for clients in every panel view.
 */

const MAC_LIKE = /^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$/i;

/** True for a locally administered (private / randomised) MAC address. */
export function isLocallyAdministered(mac: string): boolean {
  const first = parseInt(mac.replace(/[^0-9a-f]/gi, '').slice(0, 2), 16);
  return Number.isFinite(first) && (first & 0x02) !== 0;
}

/** Last two octets of a MAC for short labels: "…8d:9f". */
export function macTail(mac: string): string {
  const hex = mac.replace(/[^0-9a-f]/gi, '').toLowerCase();
  return hex.length >= 4 ? `…${hex.slice(-4, -2)}:${hex.slice(-2)}` : mac;
}

export interface ClientNameInput {
  mac: string;
  haName?: string;
  hostname?: string;
  manufacturer?: string;
  randomMac?: boolean;
}

/**
 * Best human-readable name for a client, best source first:
 * name known to Home Assistant → DHCP hostname → manufacturer + MAC tail
 * → "Privat-MAC …xx:yy" → MAC.
 */
export function clientDisplayName(c: ClientNameInput): string {
  if (c.haName) return c.haName;
  const host = (c.hostname ?? '').trim();
  if (host && host !== '*' && !MAC_LIKE.test(host)) return host;
  if (!c.mac) return host || '—';
  // A private MAC has no OUI vendor; a manufacturer here comes from HA.
  if (c.manufacturer) return `${c.manufacturer} ${macTail(c.mac)}`;
  if (c.randomMac ?? isLocallyAdministered(c.mac)) return `Privat-MAC ${macTail(c.mac)}`;
  return c.mac;
}
