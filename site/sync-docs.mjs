// Copies the canonical user docs from ../docs into Starlight's content dir at build time,
// so /docs stays the single source of truth (no drift). Adds the frontmatter Starlight needs
// (title from the leading # H1) and rewrites inter-doc .md links to site routes.
import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const docsDir = join(here, '..', 'docs');
// Nested under docs/ so every synced page routes at /docs/<slug>/ (Starlight
// derives routes from the path under src/content/docs).
const outDir = join(here, 'src', 'content', 'docs', 'docs');
mkdirSync(outDir, { recursive: true });

// slug -> { description } ; order is controlled by the sidebar in astro.config.mjs
const PAGES = {
  'getting-started': 'Install Busbar, write a minimal config, and make your first request, end to end.',
  'why-busbar': 'The case for Busbar: the problems it solves, what it enables, and how it compares.',
  'configuration': 'Full configuration reference: every key, default, and validation rule.',
  'protocols': 'The six wire protocols and lossless cross-protocol translation.',
  'providers': 'How to add any provider that speaks one of the six protocols: a config entry, no code.',
  'pools': 'What a pool is, how member selection and failover work, the full config reference, and copy-paste recipes.',
  'reliability': 'How Busbar keeps serving through provider failures: the reliability layers, tied together with one worked example.',
  'circuit-breaker': 'Fault-attributed circuit breaking: scope, failure classification, the state machine, trip conditions, cooldown, and config.',
  'failover': 'In-flight failover: the first-byte boundary, failover budget, context-length failover, session affinity, and pool exhaustion.',
  'observability': 'Health, metrics, and observability endpoints: /healthz, /stats, /metrics, and the signals worth alerting on.',
  'hooks': 'Your logic on the request path: the routing policy hook and the request-log hook, what each receives, what you control, and the fail-safe guarantees.',
  'operations': 'Running Busbar in production: process configuration, TLS and mTLS, health and readiness, metrics to watch, the admin API, and troubleshooting.',
  'architecture': 'A request traced end to end: the superset IR, the reader/writer seams behind protocols-not-providers, and failure disposition.',
  'admin-api': 'The frozen /admin/v1 management contract: reads, the config plane, hook lifecycle, keys, audit, and scopes.',
  'migration-1.3': 'The one-page 1.2.x to 1.3 config migration: every removed key and its exact replacement.',
};

const esc = (s) => s.replace(/"/g, '\\"');

// Starlight slugifies content paths (dots become dashes: migration-1.3 -> migration-1-3), so both
// the emitted filename and every rewritten inter-doc link must use the slugified form or the
// sidebar/route lookups miss.
const slugify = (name) => name.replace(/\./g, '-');

for (const [slug, description] of Object.entries(PAGES)) {
  const raw = readFileSync(join(docsDir, `${slug}.md`), 'utf8');
  const lines = raw.split('\n');

  // Pull the first H1 as the page title, drop it from the body (Starlight renders the title).
  let title = slug;
  const h1 = lines.findIndex((l) => /^#\s+/.test(l));
  if (h1 !== -1) {
    title = lines[h1].replace(/^#\s+/, '').trim();
    lines.splice(h1, 1);
    if (lines[h1] === '') lines.splice(h1, 1);
  }

  let body = lines.join('\n');
  // Rewrite inter-doc links: (foo.md) / (./foo.md) / (docs/foo.md) -> (/docs/foo/) ; README -> /
  body = body
    .replace(/\]\((?:\.\/)?(?:docs\/)?([a-z0-9.-]+)\.md(#[^)]*)?\)/gi, (_m, name, hash) =>
      name.toLowerCase() === 'readme' ? `](/${hash || ''})` : `](/docs/${slugify(name)}/${hash || ''})`)
    .replace(/\]\(\.\.\/README\.md(#[^)]*)?\)/gi, (_m, hash) => `](/${hash || ''})`);

  const frontmatter = `---\ntitle: "${esc(title)}"\ndescription: "${esc(description)}"\n---\n\n`;
  writeFileSync(join(outDir, `${slugify(slug)}.md`), frontmatter + body);
  console.log(`synced docs/${slug}.md -> src/content/docs/docs/${slug}.md  (title: ${title})`);
}

// Publish the provider catalog under our own domain (served at /providers.yaml), so the
// install flow and docs never have to point at a raw GitHub URL.
copyFileSync(join(here, '..', 'providers.yaml'), join(here, 'public', 'providers.yaml'));
console.log('published providers.yaml -> public/providers.yaml');

// Sync CHANGELOG.md from repo root into Starlight as /changelog/.
// The repo CHANGELOG.md is the single source of truth — never hand-edit the generated file.
{
  let raw = readFileSync(join(here, '..', 'CHANGELOG.md'), 'utf8');

  // The published changelog NEVER shows an "Unreleased" section — visitors see shipped versions
  // only. A dev may keep an `## [Unreleased]` block in CHANGELOG.md to stage notes; strip it here
  // (everything from that heading up to the next `## ` version heading) so it can't reach the site.
  raw = raw.replace(/^## \[Unreleased\][^\n]*\n(?:(?!^## )[\s\S])*?(?=^## |\Z)/im, '');

  // The published changelog shows 1.0.0 and later only. Pre-1.0 history (0.x releases, the
  // 1.0.0-rc.* candidates, and the Early-development block) stays in the repo CHANGELOG.md as the
  // source of truth but is hidden from the site: everything from the first pre-1.0 heading to the
  // end is dropped (only the Keep-a-Changelog reference links follow it, and those are removed
  // below anyway).
  {
    const pre = raw.match(/^## \[(?:0\.|1\.0\.0-rc\.|Early development)/m);
    if (pre) raw = raw.slice(0, pre.index).trimEnd() + '\n';
  }

  const lines = raw.split('\n');

  // Drop the leading # H1 ("# Changelog") — Starlight renders the title from frontmatter.
  const h1 = lines.findIndex((l) => /^#\s+/.test(l));
  if (h1 !== -1) {
    lines.splice(h1, 1);
    if (lines[h1] === '') lines.splice(h1, 1);
  }

  // Promote version headings and split the date onto its own styled line:
  //   ## [x.y.z], 2026-06-30   ->   ## x.y.z
  //                                 <p class="changelog-date">June 30, 2026</p>
  // Keeps the version as a clean H2 (nests under the page H1, shows in the TOC),
  // and renders the date beneath it in a smaller, muted font (see global.css).
  let body = lines.join('\n');
  body = body.replace(
    /^## \[([^\]]+)\][,:]?\s*(\d{4}-\d{2}-\d{2})?.*$/gm,
    (_m, ver, date) => {
      if (!date) return `## ${ver}`;
      const nice = new Date(date + 'T00:00:00Z').toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        timeZone: 'UTC',
      });
      return `## ${ver}\n\n<p class="changelog-date">${nice}</p>`;
    },
  );

  // Rewrite Keep-a-Changelog reference links at the bottom (e.g. [Unreleased]: https://...)
  // to plain text so they don't produce broken anchor links in the rendered page.
  body = body.replace(/^\[([^\]]+)\]: (https?:\/\/\S+)$/gm, '');

  const frontmatter = [
    '---',
    'title: "Changelog"',
    'description: "All notable changes to Busbar, newest first. Keep-a-Changelog format."',
    'tableOfContents:',
    '  minHeadingLevel: 2',
    '  maxHeadingLevel: 3',
    '---',
    '',
    '',
  ].join('\n');

  writeFileSync(join(outDir, 'changelog.md'), frontmatter + body.trimStart());
  console.log('synced CHANGELOG.md -> src/content/docs/docs/changelog.md');
}

// Expose the crate version (from the repo Cargo.toml) to the site as src/release.json,
// so pages (e.g. /download) can show the current version without reading outside site/ at
// astro-build time. Single source of truth = Cargo.toml [package] version.
{
  const cargo = readFileSync(join(here, '..', 'Cargo.toml'), 'utf8');
  const version = (cargo.match(/^\s*version\s*=\s*"([^"]+)"/m) || [])[1] || '';
  writeFileSync(join(here, 'src', 'release.json'), JSON.stringify({ version }, null, 2) + '\n');
  console.log(`wrote release version ${version || '(unknown)'} -> src/release.json`);
}
