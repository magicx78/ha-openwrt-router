/**
 * Shared VLAN color palette.
 *
 * Returns a deterministic hex color for a given VLAN id, so the same VLAN
 * always renders in the same color across the panel (port chips, VLAN
 * badges, edge labels, wiring view).
 */

export const VLAN_COLORS = [
  '#3b82f6', '#22c55e', '#f59e0b', '#8b5cf6',
  '#ef4444', '#eab308', '#14b8a6',
] as const;

export function vlanColor(vlanId: number): string {
  return VLAN_COLORS[vlanId % VLAN_COLORS.length];
}
