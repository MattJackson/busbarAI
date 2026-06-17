# Busbar — Brand Assets

Symbol-only identity (no wordmark). The mark reads as a **busbar** first — an
isolated conductor bar feeding three non-contact circuits with terminal nodes —
and resolves into a **B** on second look.

## Colors
| Token          | Hex       | Use                         |
|----------------|-----------|-----------------------------|
| Slate          | `#0F172A` | Primary surface / disc      |
| Electric lime  | `#A3E635` | Accent / the mark           |
| White          | `#FFFFFF` | Reverse / light surface     |
| Charcoal       | `#1E293B` | Secondary surface           |

## What's inside
- `svg/` — source vectors (scale to any size)
  - `busbar-primary` — slate disc, lime mark (default)
  - `busbar-inverse` — white disc, slate mark + keyline (dark/photo backgrounds)
  - `busbar-glyph-{lime,slate,white}` — mark only, no disc (inline / one-color)
  - `busbar-favicon` — bolder cut for ≤32px
- `png/` — raster exports (transparent): primary 16–1024, glyphs 512, inverse 512
- `favicon/` — `favicon.ico` (16/32/48), `apple-touch-icon.png` (180), 16/32 PNGs
- `social/` — `github-avatar.png` (460), `og-card.png` (1280×640)
- `brand/` — `busbar-brand-sheet.png`, `tokens.json`

## Usage
- Default to **primary** on light/neutral; use **inverse** on dark or photos.
- Glyph (no disc) for inline/README/terminal or one-color printing.
- Favicon cut at 32px and below. **Minimum size 16px.**
- Clear space = 25% of the mark diameter on all sides.
- Don't recolor the mark off-palette, rotate, distort, or add effects/shadows.

## Web favicon snippet
```html
<link rel="icon" href="/favicon/favicon.ico" sizes="any">
<link rel="icon" type="image/png" sizes="32x32" href="/favicon/favicon-32.png">
<link rel="apple-touch-icon" href="/favicon/apple-touch-icon.png">
```
