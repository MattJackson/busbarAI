// @ts-check
import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';
import starlightLlmsTxt from 'starlight-llms-txt';

export default defineConfig({
  site: 'https://ai-bus.bar',
  integrations: [
    starlight({
      title: 'Busbar',
      tagline: 'The reliability layer for LLM traffic',
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
          label: 'Guides',
          items: [
            { label: 'Reliability & Failover', slug: 'reliability' },
            { label: 'Protocols & Translation', slug: 'protocols' },
            { label: 'Adding a Provider', slug: 'providers' },
            { label: 'Governance', slug: 'guides/governance' },
            { label: 'Configuration', slug: 'configuration' },
          ],
        },
      ],
    }),
  ],
});
