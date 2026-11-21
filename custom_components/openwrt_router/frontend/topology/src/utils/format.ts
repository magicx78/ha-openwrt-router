/**
 * format.ts — Shared number formatting for rates and byte counters.
 *
 * One formatter per unit so every view shows the same value the same way
 * (footer, Traffic tab, detail panel and edge tooltip used to disagree).
 */

/**
 * German number (comma decimal, dot thousands) with exactly `digits`
 * decimals; '–' when unknown. Shared by every view so "5.0" never appears
 * where "5,0" is meant (also re-exported by utils/stability).
 */
export function num(value: number | null | undefined, digits = 0): string {
  if (value == null || !Number.isFinite(value)) return '–';
  const scale = 10 ** digits;
  const rounded = Math.round(value * scale) / scale || 0; // no "-0"
  return rounded.toLocaleString('de-DE', { minimumFractionDigits: digits, maximumFractionDigits: digits });
}

/** Format a rate in bit/s. Backend `*_bps` values are true bit/s. */
export function formatBitRate(bps: number | null | undefined): string {
  if (bps == null || !Number.isFinite(bps)) return '—';
  if (bps >= 1e9) return `${num(bps / 1e9, 2)} Gbit/s`;
  if (bps >= 1e6) return `${num(bps / 1e6, 1)} Mbit/s`;
  if (bps >= 1e3) return `${num(bps / 1e3)} kbit/s`;
  return `${num(bps)} bit/s`;
}

/** Format a byte counter with decimal (SI) units. */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null || !Number.isFinite(bytes)) return '—';
  if (bytes >= 1e12) return `${num(bytes / 1e12, 1)} TB`;
  if (bytes >= 1e9) return `${num(bytes / 1e9, 1)} GB`;
  if (bytes >= 1e6) return `${num(bytes / 1e6, 1)} MB`;
  if (bytes >= 1e3) return `${num(bytes / 1e3)} KB`;
  return `${num(bytes)} B`;
}
