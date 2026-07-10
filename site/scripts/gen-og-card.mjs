// Regenerate public/og-card.png (the social/link-preview image) from scripts/og-card.svg.
// The SVG embeds the brand glyph + "Busbar" wordmark + "Your AI Control Plane" slogan.
// Run: node scripts/gen-og-card.mjs   (uses the sharp dep already in the site).
import sharp from 'sharp';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
const here = dirname(fileURLToPath(import.meta.url));
const svg = readFileSync(join(here, 'og-card.svg'));
const out = join(here, '..', 'public', 'og-card.png');
const info = await sharp(svg).png().toFile(out);
console.log(`wrote og-card.png ${info.width}x${info.height}`);
