# Releasing Busbar

Cutting a release is **one dispatch**. Everything downstream is automated or self-healing.

## The one human step

Write your notes under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) (Keep-a-Changelog
headings: Added / Changed / Fixed / Security). If you leave it empty, the release notes fall back
to "Maintenance and dependency updates."

## Cut the release

Run the **Cut release** workflow (Actions → *Cut release* → Run workflow → enter e.g. `1.4.2`).
It does everything that used to be a fiddly manual checklist:

1. Bumps `crates/busbar/Cargo.toml` + `Cargo.lock`.
2. **Regenerates the committed OpenAPI schema** (`UPDATE_OPENAPI=1`) — the CI drift gate that
   fails the build if this is stale.
3. Promotes `CHANGELOG [Unreleased]` → `[version]` with today's date.
4. Commits, tags `vX.Y.Z`, pushes.

Cutting the tag is the sign-off — nothing releases without you dispatching this.

## What the tag triggers (automatic)

- **`release.yml`** — cross-compiles the 5 target binaries, SBOM, the OpenAPI asset, and the
  build-provenance **attestation** (verify with `--repo GetBusbar/busbar`).
- **`docker.yml`** — builds + pushes `getbusbar/busbar:X.Y.Z` + `latest` to Docker Hub and
  `ghcr.io/getbusbar/busbar`, cosign-signed.

## Downstream (self-healing, no action needed)

- **Homebrew** — the tap's `bump-formula` workflow runs daily and updates both `busbar` and
  `busbar-admin` formulae (version + checksums) when it sees a newer release. A missed run just
  catches up the next day. *(Optional: add a PAT + fire `repository_dispatch{type: upstream-release}`
  at the end of `release.yml` for an instant bump instead of ≤24 h.)*
- **Website** — the download page shows the new version automatically (`src/release.json` is
  regenerated from Cargo at build). For the version-**pin** examples (docker/compose/helm/attestation),
  run `node scripts/bump-site-version.mjs X.Y.Z` in the marketing repo and push — or wire a
  Cloudflare Pages deploy hook to rebuild on release. *(This never touches `facts.ts BUSBAR_VERSION`,
  which stamps measured benchmark data and only changes on a re-benchmark.)*
- **SDKs** (`busbar-python` / `-js` / `-go`, `busbar-admin`) — these carry their own semver and
  regenerate from `openapi.json`; tag them (`vX.Y.Z`) only when you want to publish a new SDK cut.
  Publishing is tokenless (OIDC / git tag).

## Honesty invariant

Every performance number the site publishes is stamped with version + hardware + source, enforced
by a build-time self-check in `facts.ts` that fails the build if a stamp is missing. Re-benchmark →
update the measured value **and** its `BUSBAR_VERSION`/hardware stamp together; never bump the stamp
without a real run behind it.
