// Docker-Hub-style count formatting: exact below 1,000, otherwise rounded UP to one decimal with
// a K/M suffix (Docker Hub shows 2,034 as "2.1K"). Trailing ".0" is dropped ("2K", not "2.0K").
export function dockerCount(n: number): string {
  if (!Number.isFinite(n) || n < 0) return '0';
  if (n < 1000) return String(Math.round(n));
  const suffix = n < 1_000_000 ? 'K' : 'M';
  const divisor = n < 1_000_000 ? 100 : 100_000; // /1000 then round up to 1 decimal
  return (Math.ceil(n / divisor) / 10).toFixed(1).replace(/\.0$/, '') + suffix;
}
