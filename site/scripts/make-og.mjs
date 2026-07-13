// Renders the "Claude Code + Busbar" OG card (1200x630) to site/public/og/claude-code-busbar.png
import sharp from 'sharp';

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <linearGradient id="bg" x1="0" y1="0" x2="1" y2="1">
      <stop offset="0" stop-color="#1e293b"/>
      <stop offset="0.55" stop-color="#0f172a"/>
      <stop offset="1" stop-color="#0b1120"/>
    </linearGradient>
  </defs>
  <rect width="1200" height="630" fill="url(#bg)"/>

  <!-- mark -->
  <rect x="72" y="70" width="20" height="20" rx="4" fill="#a3e635" transform="rotate(45 82 80)"/>
  <text x="108" y="88" font-family="Helvetica,Arial,sans-serif" font-size="24" font-weight="800" letter-spacing="6" fill="#a3e635">BUSBAR</text>

  <!-- headline -->
  <text x="70" y="238" font-family="Helvetica,Arial,sans-serif" font-size="74" font-weight="800" fill="#f8fafc">Claude Code, running on</text>
  <text x="70" y="322" font-family="Helvetica,Arial,sans-serif" font-size="74" font-weight="800" fill="#a3e635">AWS Bedrock.</text>

  <!-- flow -->
  <g font-family="'SF Mono',Menlo,monospace" font-size="26" font-weight="600">
    <rect x="70" y="404" width="228" height="58" rx="12" fill="#94a3b820" stroke="#94a3b840"/>
    <text x="184" y="441" fill="#cbd5e1" text-anchor="middle">Claude Code</text>
    <text x="320" y="441" fill="#64748b" font-size="30">&#8594;</text>
    <rect x="360" y="404" width="150" height="58" rx="12" fill="#a3e635"/>
    <text x="435" y="441" fill="#0f172a" text-anchor="middle" font-weight="700">Busbar</text>
    <text x="532" y="441" fill="#64748b" font-size="30">&#8594;</text>
    <rect x="572" y="404" width="392" height="58" rx="12" fill="#94a3b820" stroke="#94a3b840"/>
    <text x="768" y="441" fill="#cbd5e1" text-anchor="middle">Amazon Nova &#183; Bedrock</text>
  </g>

  <!-- footer -->
  <text x="70" y="560" font-family="Helvetica,Arial,sans-serif" font-size="26" font-weight="700" fill="#f8fafc">getbusbar.com</text>
  <text x="300" y="560" font-family="Helvetica,Arial,sans-serif" font-size="22" fill="#94a3b8">·  one env var &#8212; the agent never knows</text>
</svg>`;

await sharp(Buffer.from(svg)).png().toFile('public/og/claude-code-busbar.png');
console.log('OG card written to site/public/og/claude-code-busbar.png');
