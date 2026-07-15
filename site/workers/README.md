# Site Workers

Cloudflare Workers that back the dynamic bits of getbusbar.com. Static pages are the Astro build in
`site/`; anything that needs live data or storage lives here.

## docker-pulls

Live Docker Hub pull counts for the site badges, served from KV so a visitor read never hits Docker
Hub. The Worker refreshes the counts itself on an hourly **Cron Trigger** — there is no external
writer, no shared secret, and no cross-provider POST.

- `GET /api/pulls?repo=<ns>/<name>` → `{ "pull_count": <number|null> }` (reads KV)
- `scheduled` (cron, hourly) → fetches Docker Hub, writes KV

Docker Hub rate-limits by source IP and 429s Cloudflare's shared Worker egress. Setting the optional
`DOCKERHUB_USER` / `DOCKERHUB_TOKEN` secrets makes the Worker authenticate, so the limit attaches to
the account rather than the egress IP. Without them it fetches anonymously and, on a 429, simply
leaves the last good count in KV (stale, never null).

### Deploy

```sh
cd site/workers
npx wrangler deploy                 # config + Cron Trigger + route, all from wrangler.toml
npx wrangler secret put DOCKERHUB_USER    # optional
npx wrangler secret put DOCKERHUB_TOKEN   # optional (a Docker Hub access token)
```

Fill the `<PLACEHOLDER>` values in `wrangler.toml` first (account id, KV namespace id).

> History: the refresh used to run as a GitHub Actions cron that POSTed counts in over a shared
> secret. Cloudflare's bot challenge started 403-ing the runner's datacenter IP, so the write never
> reached the Worker. Moving the fetch into a Cron Trigger removed the cross-provider seam entirely.
