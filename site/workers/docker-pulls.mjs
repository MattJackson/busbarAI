// Cloudflare Worker: live Docker Hub pull counts, served from KV so a visitor read never touches
// Docker Hub (which 429s Cloudflare egress IPs). A GitHub Actions cron (.github/workflows/
// docker-pulls.yml) fetches the counts from GitHub's non-blocked IPs every hour and POSTs them here.
//
//   GET  /api/pulls?repo=<ns>/<name>              -> { "pull_count": <number|null> }   (reads KV)
//   POST /api/pulls   Authorization: Bearer <s>   -> writes KV   (body: {repo, pull_count})
//
// Bindings (set at deploy, not in source): PULLS_KV (kv_namespace), WRITE_SECRET (secret_text).
// Allow-listed to the images we ship, so it can never be an open proxy.
const ALLOWED = new Set(['getbusbar/busbar', 'getbusbar/headroom-hook']);

export default {
  async fetch(request, env) {
    // ── write path: cron pushes fresh counts in ──
    if (request.method === 'POST') {
      if ((request.headers.get('authorization') || '') !== `Bearer ${env.WRITE_SECRET}`) {
        return json({ error: 'unauthorized' }, 401);
      }
      let body;
      try { body = await request.json(); } catch { return json({ error: 'bad json' }, 400); }
      const { repo, pull_count } = body || {};
      if (!ALLOWED.has(repo) || typeof pull_count !== 'number' || pull_count < 0) {
        return json({ error: 'bad body' }, 400);
      }
      await env.PULLS_KV.put(`pulls:${repo}`, String(Math.round(pull_count)));
      return json({ ok: true, repo, pull_count: Math.round(pull_count) });
    }

    // ── read path: what the badge hits ──
    const repo = new URL(request.url).searchParams.get('repo') || '';
    if (!ALLOWED.has(repo)) return json({ error: 'unknown repo' }, 400);
    const v = await env.PULLS_KV.get(`pulls:${repo}`);
    return json({ pull_count: v != null ? parseInt(v, 10) : null });
  },
};

function json(obj, status = 200) {
  const cacheable = status === 200 && typeof obj.pull_count === 'number';
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      'content-type': 'application/json',
      'cache-control': cacheable ? 'public, max-age=300' : 'no-store',
      'access-control-allow-origin': '*',
    },
  });
}
