# busbar — project instructions

## Changelog

- **The published changelog (getbusbar.com/docs/changelog/) must NEVER show an "Unreleased"
  section.** Visitors see shipped versions only. `CHANGELOG.md` is the single source of truth and
  is synced to the site by `site/sync-docs.mjs`, which strips any `## [Unreleased]` block at build
  time — so a dev *may* stage notes under `## [Unreleased]` locally, but they will not publish.
  When cutting a release, rename `## [Unreleased]` to `## [X.Y.Z], YYYY-MM-DD` and bump
  `Cargo.toml`.

## Release naming

- Image/version tags are clean semver only: `X.Y.Z` + `latest`. No `.sig`/sha/test tags on Docker
  Hub. cosign signs GHCR only.
