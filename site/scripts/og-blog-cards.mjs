// Render a custom OG card (1200x630) for every blog post in the house og-card style:
// dark navy field, lime glyph + white wordmark lockup, white hero, lime subhead, mono muted
// tagline, thin lime/slate rules. Same template as og-claude-code.mjs, driven by a per-post table.
// Run: node scripts/og-blog-cards.mjs
import sharp from 'sharp';
import { writeFileSync, readFileSync } from 'node:fs';

const glyph = readFileSync(new URL('../src/assets/busbar-glyph-lime.svg', import.meta.url), 'utf8')
  .replace(/^<svg[^>]*>/, '')
  .replace(/<\/svg>\s*$/, '')
  .replaceAll('currentColor', '#A3E635');

// hero: big white line; sub: lime accent; tag: mono muted one-liner. heroSize/subSize override
// the defaults when a line is long. `out` is the /og/<file>.png the post's frontmatter points at.
const CARDS = [
  { out: 'busbar-1-0-stable',        hero: 'Busbar 1.0',        sub: 'is stable',                    tag: 'The control plane holds.' },
  { out: 'busbar-1-2-more-than-chat', hero: 'Busbar 1.2',       sub: 'more than chat',               tag: 'Every operation, every protocol.' },
  { out: 'busbar-1-3-the-api-release', hero: 'Busbar 1.3',      sub: 'your code on the request path', subSize: 48, tag: 'Hooks: tap, gate, rewrite.' },
  { out: 'busbar-in-numbers',        hero: 'Busbar, in numbers', heroSize: 82, sub: 'measured, not claimed', tag: 'Latency, size, throughput.' },
  { out: 'headroom-compression-hook', hero: 'Headroom',         sub: 'a compression hook',           tag: 'It reports its own savings.' },
  { out: 'rc1-first-release-candidate', hero: 'Release Candidate 1', heroSize: 74, sub: 'the first cut', tag: 'Six protocols. One binary.' },
  { out: 'smart-routing-today',      hero: 'Smart routing',     sub: 'is a hook',                    tag: 'Route by cost, latency, live load.' },
  { out: 'valuable-before-the-second-provider', hero: 'Valuable before', heroSize: 82, sub: 'the second provider', tag: 'One provider is enough to win.' },
  { out: 'why-im-building-busbar',   hero: "Why I'm building",  sub: 'Busbar',                       tag: 'The seam belongs in the control plane.' },
  // Hook detail pages (wired via PageLayout ogImage, not blog frontmatter).
  { out: 'hooks-headroom',           hero: 'Headroom',          sub: 'compression, on the path',     tag: 'Sub-millisecond overhead. Every model.' },
];

const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function card({ hero, sub, tag, heroSize = 92, subSize = 54 }) {
  return `<svg width="1200" height="630" viewBox="0 0 1200 630" xmlns="http://www.w3.org/2000/svg">
  <rect width="1200" height="630" fill="#0d1526"/>
  <line x1="0"   y1="140" x2="330"  y2="140" stroke="#a3e635" stroke-width="2" opacity="0.85"/>
  <line x1="870" y1="140" x2="1200" y2="140" stroke="#a3e635" stroke-width="2" opacity="0.85"/>
  <line x1="0"   y1="497" x2="330"  y2="497" stroke="#64748b" stroke-width="1" opacity="0.6"/>
  <line x1="870" y1="497" x2="1200" y2="497" stroke="#64748b" stroke-width="1" opacity="0.6"/>
  <g transform="translate(497 60) scale(0.55)">${glyph}</g>
  <text x="578" y="108" font-family="Helvetica Neue, Helvetica, Arial, sans-serif" font-size="46"
        font-weight="800" fill="#ffffff">Busbar</text>
  <text x="600" y="295" text-anchor="middle" font-family="Helvetica Neue, Helvetica, Arial, sans-serif"
        font-size="${heroSize}" font-weight="800" fill="#ffffff" letter-spacing="-2">${esc(hero)}</text>
  <text x="600" y="392" text-anchor="middle" font-family="Helvetica Neue, Helvetica, Arial, sans-serif"
        font-size="${subSize}" font-weight="700" fill="#a3e635">${esc(sub)}</text>
  <text x="600" y="555" text-anchor="middle" font-family="Menlo, SFMono-Regular, monospace"
        font-size="30" fill="#94a3b8">${esc(tag)}</text>
</svg>`;
}

for (const c of CARDS) {
  const png = await sharp(Buffer.from(card(c)), { density: 144 }).resize(1200, 630).png().toBuffer();
  writeFileSync(new URL(`../public/og/${c.out}.png`, import.meta.url), png);
  console.log(`wrote public/og/${c.out}.png ${png.length} bytes`);
}
