// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLlmsTxt from 'starlight-llms-txt';

export default defineConfig({
  site: 'https://getbusbar.com',
  // Docs live under /docs/*. Old flat URLs redirect permanently so external links,
  // search results, and the CHANGELOG's historical links keep working.
  redirects: {
    '/docs': '/docs/why-busbar/',
    '/why-busbar': '/docs/why-busbar/',
    '/getting-started': '/docs/getting-started/',
    '/pools': '/docs/pools/',
    '/routing': '/docs/routing/',
    '/protocols': '/docs/protocols/',
    '/reliability': '/docs/reliability/',
    '/circuit-breaker': '/docs/circuit-breaker/',
    '/failover': '/docs/failover/',
    '/observability': '/docs/observability/',
    '/providers': '/docs/providers/',
    '/guides/governance': '/docs/guides/governance/',
    '/security': '/docs/security/',
    '/configuration': '/docs/configuration/',
    '/benchmark': '/docs/benchmark/',
    '/changelog': '/docs/changelog/',
    // Never published at the old flat URLs, but published pages linked there anyway.
    '/operations': '/docs/operations/',
    '/architecture': '/docs/architecture/',
  },
  integrations: [
    starlight({
      title: 'Busbar',
      tagline: 'The reliability layer for LLM traffic',
      favicon: '/favicon.svg',
      logo: { src: './src/assets/busbar-glyph.svg', alt: 'Busbar' },
      customCss: ['./src/styles/global.css'],
      // Docs header carries the website's nav links (Blog, Download) so docs
      // pages can reach the rest of the site — see DocsHeaderLinks.astro.
      components: { SocialIcons: './src/components/DocsHeaderLinks.astro' },
      head: [
        // Privacy-friendly analytics by Plausible, self-hosted through a first-party
        // proxy at /relay/* (adblock-resistant). Docs pages; custom pages get the
        // equivalent via src/components/Analytics.astro. The `endpoint` is required —
        // the script defaults to plausible.io/api/event, so without it events bypass
        // the proxy.
        {
          tag: 'script',
          attrs: { async: true, src: 'https://getbusbar.com/relay/js/script.js' },
        },
        {
          tag: 'script',
          content:
            'window.plausible=window.plausible||function(){(plausible.q=plausible.q||[]).push(arguments)},plausible.init=plausible.init||function(i){plausible.o=i||{}};plausible.init({endpoint:"https://getbusbar.com/relay/api/event"})',
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
            'Self-hosted LLM gateway and control plane in a single Rust binary. One endpoint accepts any of six wire protocols (OpenAI, Anthropic, Gemini, Bedrock, Cohere, Responses), routes to weighted pools of backends, translates losslessly between protocols, and keeps serving through provider failures via fault-attributed circuit breaking and in-flight failover.',
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
            { label: 'Why Busbar', slug: 'docs/why-busbar' },
            { label: 'Getting Started', slug: 'docs/getting-started' },
          ],
        },
        {
          label: 'Core concepts',
          items: [
            { label: 'Pools', slug: 'docs/pools' },
            { label: 'Routing Policies', slug: 'docs/routing' },
            { label: 'Protocols & Translation', slug: 'docs/protocols' },
          ],
        },
        {
          label: 'Reliability',
          items: [
            { label: 'Overview', slug: 'docs/reliability' },
            { label: 'Circuit Breaker', slug: 'docs/circuit-breaker' },
            { label: 'In-flight Failover', slug: 'docs/failover' },
            { label: 'Health & Observability', slug: 'docs/observability' },
          ],
        },
        {
          label: 'Operate',
          items: [
            { label: 'Adding a Provider', slug: 'docs/providers' },
            { label: 'Governance', slug: 'docs/guides/governance' },
            { label: 'Security', slug: 'docs/security' },
            { label: 'Configuration', slug: 'docs/configuration' },
            { label: 'Operations', slug: 'docs/operations' },
          ],
        },
        {
          label: 'Reference',
          items: [
            { label: 'Architecture', slug: 'docs/architecture' },
            { label: 'Benchmark', slug: 'docs/benchmark' },
            { label: 'Changelog', slug: 'docs/changelog' },
          ],
        },
      ],
    }),
  ],
});
