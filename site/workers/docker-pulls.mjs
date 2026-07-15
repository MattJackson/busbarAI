// Cloudflare Worker: live Docker Hub pull counts, served from KV so a visitor read never touches
// Docker Hub. The Worker refreshes the counts itself on a Cron Trigger (see wrangler.toml) — there
// is no external writer, no shared secret, and no cross-provider POST.
//
//   GET       /api/pulls?repo=<ns>/<name>   -> { "pull_count": <number|null> }   (reads KV)
//   scheduled (cron, hourly)                -> fetch Docker Hub, write KV
//
// Why the Worker fetches directly now: Docker Hub rate-limits by source IP, and Cloudflare's shared
// Worker egress IPs get 429'd on anonymous requests. Authenticating (DOCKERHUB_USER / DOCKERHUB_TOKEN)
// attaches the limit to the account instead of the egress IP, which lifts the block. Auth is optional:
// with no creds the Worker tries anonymously and simply leaves the last good count in place if it 429s.
//
// Bindings (set at deploy via wrangler.toml + `wrangler secret put`, not in source):
//   PULLS_KV        kv_namespace
//   DOCKERHUB_USER  secret_text (optional)
//   DOCKERHUB_TOKEN secret_text (optional; a Docker Hub access token, not the account password)
//
// Allow-listed to the images we ship, so it can never be pointed at an arbitrary repo.
const ALLOWED = ['getbusbar/busbar', 'getbusbar/headroom-hook'];
const ALLOWED_SET = new Set(ALLOWED);

export default {
  // ── read path: what the badge hits ──
  async fetch(request, env) {
    const repo = new URL(request.url).searchParams.get('repo') || '';
    if (!ALLOWED_SET.has(repo)) return json({ error: 'unknown repo' }, 400);
    const v = await env.PULLS_KV.get(`pulls:${repo}`);
    return json({ pull_count: v != null ? parseInt(v, 10) : null });
  },

  // ── refresh path: the Cron Trigger fires this hourly ──
  async scheduled(_event, env, _ctx) {
    const token = await dockerHubToken(env);
    for (const repo of ALLOWED) {
      try {
        const n = await fetchPullCount(repo, token);
        await env.PULLS_KV.put(`pulls:${repo}`, String(n));
        console.log(`updated ${repo} = ${n}`);
      } catch (err) {
        // Leave the last good value in KV — a transient 429/5xx yields stale, never null.
        console.log(`skip ${repo}: ${err.message}`);
      }
    }
  },
};

// Exchange Docker Hub creds for a JWT so rate limits attach to the account, not the egress IP.
// Returns null when no creds are configured (anonymous best-effort).
async function dockerHubToken(env) {
  if (!env.DOCKERHUB_USER || !env.DOCKERHUB_TOKEN) return null;
  const res = await fetch('https://hub.docker.com/v2/users/login/', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'user-agent': UA },
    body: JSON.stringify({ username: env.DOCKERHUB_USER, password: env.DOCKERHUB_TOKEN }),
  });
  if (!res.ok) throw new Error(`docker hub login ${res.status}`);
  const { token } = await res.json();
  return token || null;
}

// Fetch one repo's pull_count, with a small retry so a single 429/5xx doesn't skip the update.
async function fetchPullCount(repo, token) {
  const headers = { 'user-agent': UA, accept: 'application/json' };
  if (token) headers.authorization = `Bearer ${token}`;
  let lastStatus = 0;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt) await sleep(500 * attempt);
    const res = await fetch(`https://hub.docker.com/v2/repositories/${repo}/`, { headers });
    if (res.ok) {
      const { pull_count } = await res.json();
      if (typeof pull_count !== 'number' || pull_count < 0) throw new Error('bad pull_count');
      return Math.round(pull_count);
    }
    lastStatus = res.status;
    if (res.status !== 429 && res.status < 500) break; // 4xx (not 429) won't fix itself
  }
  throw new Error(`docker hub ${lastStatus}`);
}

const UA = 'getbusbar-pulls-worker (+https://getbusbar.com)';
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

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
