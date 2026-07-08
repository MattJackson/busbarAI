// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLlmsTxt from 'starlight-llms-txt';

export default defineConfig({
  site: 'https://getbusbar.com',
  integrations: [
    starlight({
      title: 'Busbar',
      tagline: 'The reliability layer for LLM traffic',
      favicon: '/favicon.svg',
      logo: { src: './src/assets/busbar-glyph.svg', alt: 'Busbar' },
      customCss: ['./src/styles/global.css'],
      head: [
        // Privacy-friendly analytics by Plausible (docs pages; custom pages get the
        // equivalent via src/components/Analytics.astro).
        {
          tag: 'script',
          attrs: { async: true, src: 'https://plausible.io/js/pa-Bzy5HbSMKIad_GF6O63BU.js' },
        },
        {
          tag: 'script',
          content:
            'window.plausible=window.plausible||function(){(plausible.q=plausible.q||[]).push(arguments)},plausible.init=plausible.init||function(i){plausible.o=i||{}};plausible.init()',
        },
        { tag: 'link', attrs: { rel: 'icon', href: '/favicon.ico', sizes: 'any' } },
        { tag: 'link', attrs: { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' } },
        { tag: 'meta', attrs: { property: 'og:image', content: 'https://getbusbar.com/og-card.png' } },
        { tag: 'meta', attrs: { name: 'twitter:card', content: 'summary_large_image' } },
        { tag: 'meta', attrs: { name: 'twitter:image', content: 'https://getbusbar.com/og-card.png' } },
        // schema.org JSON-LD on every docs page (Organization + WebSite).
        {
          tag: 'script',
          attrs: { type: 'application/ld+json' },
          content:
            '{"@context":"https://schema.org","@type":"Organization","name":"Busbar","url":"https://getbusbar.com","logo":"https://getbusbar.com/favicon.svg","sameAs":["https://github.com/MattJackson/busbarAI"]}',
        },
        {
          tag: 'script',
          attrs: { type: 'application/ld+json' },
          content:
            '{"@context":"https://schema.org","@type":"WebSite","name":"Busbar","url":"https://getbusbar.com"}',
        },
      ],
      // Generates /llms.txt (curated index) and /llms-full.txt (entire docs as one
      // Markdown file) so an agent can ingest the whole site in a single fetch.
      plugins: [
        starlightLlmsTxt({
          projectName: 'Busbar',
          description:
            'Self-hosted LLM gateway in a single Rust binary. One endpoint accepts any of six wire protocols (OpenAI, Anthropic, Gemini, Bedrock, Cohere, Responses), routes to weighted pools of backends, translates losslessly between protocols, and keeps serving through provider failures via fault-attributed circuit breaking and in-flight failover.',
        }),
      ],
      social: [
        { icon: 'github', label: 'GitHub', href: 'https://github.com/MattJackson/busbarAI' },
        { icon: 'discord', label: 'Discord', href: 'https://discord.gg/f5XtWw4NT' },
      ],
      sidebar: [
        {
          label: 'Start here',
          items: [
            { label: 'Why Busbar', slug: 'why-busbar' },
            { label: 'Getting Started', slug: 'getting-started' },
          ],
        },
        {
          label: 'Core concepts',
          items: [
            { label: 'Pools', slug: 'pools' },
            { label: 'Routing Policies', slug: 'routing' },
            { label: 'Protocols & Translation', slug: 'protocols' },
          ],
        },
        {
          label: 'Reliability',
          items: [
            { label: 'Overview', slug: 'reliability' },
            { label: 'Circuit Breaker', slug: 'circuit-breaker' },
            { label: 'In-flight Failover', slug: 'failover' },
            { label: 'Health & Observability', slug: 'observability' },
          ],
        },
        {
          label: 'Operate',
          items: [
            { label: 'Adding a Provider', slug: 'providers' },
            { label: 'Governance', slug: 'guides/governance' },
            { label: 'Security', slug: 'security' },
            { label: 'Configuration', slug: 'configuration' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Benchmark', slug: 'benchmark' },
            { label: 'Changelog', slug: 'changelog' },
          ],
        },
      ],
    }),
  ],
});
