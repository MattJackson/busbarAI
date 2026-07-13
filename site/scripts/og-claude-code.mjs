// Render the "Claude Code + Busbar" OG card (1200x630) in the house og-card style:
// dark navy field, lime glyph + white wordmark lockup, lime subhead, mono muted tagline,
// thin lime rules. Run: node scripts/og-claude-code.mjs
import sharp from 'sharp';
import { readFileSync, writeFileSync } from 'node:fs';

const glyph = readFileSync(new URL('../src/assets/busbar-glyph-lime.svg', import.meta.url), 'utf8')
  // strip the outer <svg> so it can be inlined as a group
  .replace(/^<svg[^>]*>/, '')
  .replace(/<\/svg>\s*$/, '')
  .replaceAll('currentColor', '#A3E635');

const svg = `<svg width="1200" height="630" viewBox="0 0 1200 630" xmlns="http://www.w3.org/2000/svg">
  <rect width="1200" height="630" fill="#0d1526"/>

  <!-- thin lime rules, house style -->
  <line x1="0"   y1="140" x2="330"  y2="140" stroke="#a3e635" stroke-width="2" opacity="0.85"/>
  <line x1="870" y1="140" x2="1200" y2="140" stroke="#a3e635" stroke-width="2" opacity="0.85"/>
  <line x1="0"   y1="497" x2="330"  y2="497" stroke="#64748b" stroke-width="1" opacity="0.6"/>
  <line x1="870" y1="497" x2="1200" y2="497" stroke="#64748b" stroke-width="1" opacity="0.6"/>

  <!-- Busbar lockup, small, top-center -->
  <g transform="translate(497 60) scale(0.55)">${glyph}</g>
  <text x="578" y="108" font-family="Helvetica Neue, Helvetica, Arial, sans-serif" font-size="46"
        font-weight="800" fill="#ffffff">Busbar</text>

  <!-- hero -->
  <text x="600" y="295" text-anchor="middle" font-family="Helvetica Neue, Helvetica, Arial, sans-serif"
        font-size="92" font-weight="800" fill="#ffffff" letter-spacing="-2">Claude Code</text>
  <text x="600" y="392" text-anchor="middle" font-family="Helvetica Neue, Helvetica, Arial, sans-serif"
        font-size="54" font-weight="700" fill="#a3e635">running on AWS Bedrock</text>

  <!-- mono tagline, muted, house style -->
  <text x="600" y="555" text-anchor="middle" font-family="Menlo, SFMono-Regular, monospace"
        font-size="30" fill="#94a3b8">One env var. The agent never knows.</text>
</svg>`;

// render at 2x density for crisp text, then downscale to the standard OG 1200x630
const png = await sharp(Buffer.from(svg), { density: 144 }).resize(1200, 630).png().toBuffer();
writeFileSync(new URL('../public/og/claude-code-busbar.png', import.meta.url), png);
console.log('wrote public/og/claude-code-busbar.png', png.length, 'bytes');
