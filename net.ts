// net.ts — shared network guards for Marque. Internal: not in package.json
// "exports", so consumers can't import it — only marque.ts and optional
// modules (x.ts) do. Keeping ONE copy of these red-team-hardened guards is
// the point; don't fork them.
import { isIP } from 'node:net';

// SSRF guard (red-team must-fix): origin must be a public https hostname.
export function assertPublicHost(origin: string): void {
  // no scheme/port/path/userinfo/query/fragment/whitespace (IPv6 has colons → also rejected here)
  if (origin === '' || /[:/\\@?#\s]/.test(origin)) throw new Error('marque: bad origin');
  let host: string;
  try { host = new URL('https://' + origin).hostname; }
  catch { throw new Error('marque: bad origin'); }
  // URL normalizes shorthand/octal/hex IPv4 (127.1 → 127.0.0.1); isIP rejects EVERY
  // IP literal form — a strict dotted-quad regex would miss the short forms.
  if (isIP(host)) throw new Error('marque: ip origin not allowed');
  const h = host.replace(/\.$/, '').toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost') || h.endsWith('.internal') ||
      h.endsWith('.local') || !h.includes('.'))
    throw new Error('marque: non-public origin');
}

// Bounded JSON fetch: 3s timeout, no redirect follow, 64KB cap, null on any
// failure (fail closed — callers treat null as "nothing published").
export async function boundedJson(url: string): Promise<any> {
  const ac = new AbortController();
  const t = setTimeout(() => ac.abort(), 3000);
  try {
    const r = await fetch(url, {
      redirect: 'error',                                  // no cross-origin redirect follow
      signal: ac.signal,
      headers: { accept: 'application/json' },
    });
    if (!r.ok) return null;
    if (Number(r.headers.get('content-length')) > 64 * 1024) return null;  // reject honest-huge bodies
    // chunked/no-length bodies still bounded by the 3s timeout
    return JSON.parse((await r.text()).slice(0, 64 * 1024));
  } catch { return null; }
  finally { clearTimeout(t); }
}
