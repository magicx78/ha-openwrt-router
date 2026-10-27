/**
 * format.ts — Shared number formatting for rates and byte counters.
 *
 * One formatter per unit so every view shows the same value the same way
 * (footer, Traffic tab, detail panel and edge tooltip used to disagree).
 */

/** Format a rate in bit/s. Backend `*_bps` values are true bit/s. */
export function formatBitRate(bps: number | null | undefined): string {
  if (bps == null || !Number.isFinite(bps)) return '—';
  if (bps >= 1e9) return `${(bps / 1e9).toFixed(2)} Gbit/s`;
  if (bps >= 1e6) return `${(bps / 1e6).toFixed(1)} Mbit/s`;
  if (bps >= 1e3) return `${(bps / 1e3).toFixed(0)} kbit/s`;
  return `${Math.round(bps)} bit/s`;
}

/** Format a byte counter with decimal (SI) units. */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || !Number.isFinite(bytes)) return '—';
  if (bytes >= 1e9) return `${(bytes / 1e9).toFixed(1)} GB`;
  if (bytes >= 1e6) return `${(bytes / 1e6).toFixed(1)} MB`;
  if (bytes >= 1e3) return `${(bytes / 1e3).toFixed(0)} KB`;
  return `${bytes} B`;
}
