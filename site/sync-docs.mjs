// Copies the canonical user docs from ../docs into Starlight's content dir at build time,
// so /docs stays the single source of truth (no drift). Adds the frontmatter Starlight needs
// (title from the leading # H1) and rewrites inter-doc .md links to site routes.
import { readFileSync, writeFileSync, mkdirSync, copyFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));
const docsDir = join(here, '..', 'docs');
const outDir = join(here, 'src', 'content', 'docs');
mkdirSync(outDir, { recursive: true });

// slug -> { description } ; order is controlled by the sidebar in astro.config.mjs
const PAGES = {
  'getting-started': 'Install Busbar, write a minimal config, and make your first request — end to end.',
  'why-busbar': 'The case for Busbar: the problems it solves, what it enables, and how it compares.',
  'configuration': 'Full configuration reference — every key, default, and validation rule.',
  'protocols': 'The six wire protocols and lossless cross-protocol translation.',
  'providers': 'How to add any provider that speaks one of the six protocols — a config entry, no code.',
  'reliability': 'Pools, fault-attributed circuit breaking, in-flight failover, and governance.',
};

const esc = (s) => s.replace(/"/g, '\\"');

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
  // Rewrite inter-doc links: (foo.md) / (./foo.md) / (docs/foo.md) -> (/foo/) ; README -> /
  body = body
    .replace(/\]\((?:\.\/)?(?:docs\/)?([a-z0-9-]+)\.md(#[^)]*)?\)/gi, (_m, name, hash) =>
      name.toLowerCase() === 'readme' ? `](/${hash || ''})` : `](/${name}/${hash || ''})`)
    .replace(/\]\(\.\.\/README\.md(#[^)]*)?\)/gi, (_m, hash) => `](/${hash || ''})`);

  const frontmatter = `---\ntitle: "${esc(title)}"\ndescription: "${esc(description)}"\n---\n\n`;
  writeFileSync(join(outDir, `${slug}.md`), frontmatter + body);
  console.log(`synced docs/${slug}.md -> src/content/docs/${slug}.md  (title: ${title})`);
}

// Publish the provider catalog under our own domain (served at /providers.yaml), so the
// install flow and docs never have to point at a raw GitHub URL.
copyFileSync(join(here, '..', 'providers.yaml'), join(here, 'public', 'providers.yaml'));
console.log('published providers.yaml -> public/providers.yaml');
