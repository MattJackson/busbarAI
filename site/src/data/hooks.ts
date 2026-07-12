// Single source of truth for the Hook Store. Read by the store index
// (src/pages/hooks.astro) and the per-hook detail pages
// (src/pages/hooks/[slug].astro).
//
//   kind    tap | gate — the two hook types.
//   status  'Available' (shippable, green + repo link) · 'Coming soon' (built,
//           not yet linkable, amber) · 'Example' (a template to fork, amber +
//           repo link) · 'Idea' (not built — a prompt for what's possible) ·
//           'Yours' (the submit-your-own CTA card; cta: true, no detail page).
//   href    Where the card links. '/hooks/{slug}' for a hook with its own detail
//           page (Headroom), an external/blog URL (Smart Router → the write-up),
//           or omitted so the card isn't clickable (Ideas, for now).
//   detail  Longer copy for a hook's own page (array of HTML paragraphs). A page
//           is generated only when href points at that page (`/hooks/{slug}`);
//           Ideas keep detail copy ready for when they graduate, but get no page
//           yet because they have no such href.

export const GITHUB = 'https://github.com/MattJackson/busbarAI';

export interface Hook {
  slug: string;
  name: string;
  kind: 'tap' | 'gate';
  tagline: string;
  body: string;
  status: 'Available' | 'Coming soon' | 'Example' | 'Idea' | 'Yours';
  repo?: string | null;
  linkLabel?: string;
  note?: string;
  cta?: boolean;
  href?: string;
  external?: boolean;
  detail?: string[];
  // "Our hook" links shown top-right on the detail page (our GitHub, install info)
  // — clearly OUR side: our page, our hook, how to get it.
  hookRepo?: string;
  install?: { note: string; code?: string };
  // When a hook wraps someone else's open-source project, `spotlight` credits it
  // loudly on the detail page — the point is free advertising for the creator,
  // not quiet attribution. `links` render as a labelled resource list.
  spotlight?: {
    project: string;
    developer: string;
    blurb: string;
    // `icon` selects which logo to render (see the detail page's ICONS map).
    links: { label: string; url: string; icon: 'web' | 'github' | 'developer' | 'discord' }[];
  };
}

export const kindLabel: Record<'tap' | 'gate', string> = { tap: 'Tap', gate: 'Gate' };

export const hooks: Hook[] = [
  {
    slug: 'headroom',
    name: 'Headroom',
    kind: 'gate',
    tagline: 'Context compression, on the path.',
    body: 'A rewrite gate that trims and compacts a request’s context before it ships — so a long conversation stays under the window without your app rebuilding the prompt. Written once, it works against every protocol and provider Busbar speaks.',
    repo: null,
    status: 'Coming soon',
    href: '/hooks/headroom',
    hookRepo: 'https://github.com/GetBusbar',
    install: {
      note: 'Register the hook in your Busbar config under a <code>hooks:</code> block, or attach it over the admin API. The Headroom gate is landing soon — this is the shape it will take:',
      code: `hooks:
  headroom:
    kind: gate
    global: true        # attach to every request
    # compress context before the request ships`,
    },
    note: 'Powered by the open-source <a href="https://github.com/headroomlabs-ai/headroom" target="_blank" rel="noopener">Headroom</a> project.',
    detail: [
      'Every tool call, DB query, file read, and RAG retrieval your agent makes is mostly boilerplate — noise the model pays to read on every request. Trimming it away usually means bespoke work in each app, rebuilt for every provider whose limits differ.',
      'The <a href="https://github.com/headroomlabs-ai/headroom" target="_blank" rel="noopener">Headroom</a> project already solves the hard part: it compresses that boilerplate away before it hits the model, so the LLM sees less noise, responds faster, and costs less. The Busbar hook is a thin <strong>rewrite gate</strong> that runs it on the path — it hands each request to Headroom before it ships, no app changes required.',
      'Because the gate fires on Busbar’s normalized IR, that one integration covers every wire protocol and provider at once, with failover and circuit breaking underneath it. Headroom does the compression; Busbar puts it in front of every model you call.',
    ],
    spotlight: {
      project: 'Headroom',
      developer: 'Tejas Chopra',
      blurb: 'Every tool call, DB query, file read, and RAG retrieval your agent makes is 70-95% boilerplate. Headroom compresses it away before it hits the model. The LLM sees less noise, responds faster, and costs less.',
      links: [
        { label: 'Project site', url: 'https://headroomlabs-ai.github.io/headroom/', icon: 'web' },
        { label: 'Source on GitHub', url: 'https://github.com/headroomlabs-ai/headroom', icon: 'github' },
        { label: 'Tejas Chopra', url: 'https://github.com/chopratejas', icon: 'developer' },
        { label: 'Discord', url: 'https://discord.com/invite/yRmaUNpsPJ', icon: 'discord' },
      ],
    },
  },
  {
    slug: 'smart-router',
    name: 'Smart Router',
    kind: 'gate',
    tagline: 'Route by cost, latency, and live load.',
    body: 'A worked example, not a finished product: a routing gate that picks the backend per request from real signals — each member’s cost, latency, live concurrency, and rate headroom. It’s a template to read, fork, and shape into the router you actually want.',
    repo: `${GITHUB}/tree/main/examples/smart-router`,
    linkLabel: 'View the example →',
    status: 'Example',
    href: '/blog/smart-routing-today/',
    note: 'Read the write-up: <a href="/blog/smart-routing-today/">the smart router you want is a hook</a>.',
  },
  {
    slug: 'your-hook',
    name: 'Your hook',
    kind: 'gate',
    tagline: 'Built something worth sharing?',
    body: 'A guardrail, a router, a cost meter, an audit sink — anything that runs on the path. Tell us what it does and where it lives, and we’ll list it here and link straight to your repo.',
    note: 'Email us, or open a PR against <a href="https://github.com/MattJackson/busbarAI" target="_blank" rel="noopener">the repo</a>.',
    repo: null,
    status: 'Yours',
    cta: true,
  },
  {
    slug: 'pii-guard',
    name: 'PII Guard',
    kind: 'gate',
    tagline: 'Redact sensitive data before it leaves.',
    body: 'A gate that inspects and rewrites the request body, stripping or masking sensitive data — credit-card numbers, SSNs and other socials, patient records — before it reaches any provider. One guard covers every model behind Busbar, so the redaction rule lives in one place, not in every app.',
    repo: null,
    status: 'Idea',
    detail: [
      'Sensitive data has a way of ending up in prompts: a support transcript with a credit-card number, a form with an SSN, a note with patient records. Once it reaches a provider it’s out of your hands — logged, retained, maybe used for training.',
      'PII Guard is a <strong>rewrite gate</strong> that inspects the outbound request body and strips or masks sensitive fields before the request ever leaves Busbar. Credit-card numbers, SSNs and other socials, health records — matched against rules you set, redacted in one place.',
      'One guard sits in front of every model behind Busbar, so the redaction policy is defined once instead of copied into every app and every provider integration.',
    ],
  },
  {
    slug: 'secret-shield',
    name: 'Secret Shield',
    kind: 'gate',
    tagline: 'Keep your .env out of the prompt.',
    body: 'AI coding agents load your <code>.env</code> into memory and can slip those secrets into a prompt — where they get logged, committed, or exfiltrated. A gate that scrubs the outbound body against your registered secrets catches them before the request ever leaves, for every provider at once.',
    repo: null,
    status: 'Idea',
    detail: [
      'AI coding agents load your <code>.env</code> into memory to run your project — API keys, tokens, database passwords and all. From there a secret can slip into a prompt the agent sends to a model, where it gets logged, committed to a branch, or exfiltrated through a tool call.',
      'Secret Shield is a <strong>rewrite gate</strong> that scrubs the outbound request body against the secrets you register. If a value that should never leave your machine shows up in a request, the gate catches it before the request leaves Busbar.',
      'One shield covers every provider at once. The secrets stay yours, and the check happens on the path rather than depending on every tool to behave.',
    ],
  },
  {
    slug: 'siem-audit',
    name: 'SIEM Audit',
    kind: 'tap',
    tagline: 'Every call, in your security stack.',
    body: 'A fire-and-forget tap that streams the full request and response to your SIEM or compliance archive without touching the hop. A complete, provider-agnostic audit trail for every AI call your org makes.',
    repo: null,
    status: 'Idea',
    detail: [
      'Security and compliance teams want a record of every AI call an organisation makes — who asked what, which model answered, when. Assembling that from per-app logs is patchy and provider-specific.',
      'SIEM Audit is a <strong>tap</strong>: a fire-and-forget observer that sees the full request and response and streams it to your SIEM or compliance archive. Because it runs alongside the request, nothing waits on it — the audit trail never adds latency to a call.',
      'Prometheus metrics and OTLP traces are already built into Busbar; this tap is for the security-stack destination. One tap produces a complete, provider-agnostic audit trail across every model.',
    ],
  },
  {
    slug: 'semantic-cache',
    name: 'Semantic Cache',
    kind: 'gate',
    tagline: 'Skip the call when you already know the answer.',
    body: 'A gate that recognises a request it has answered before and short-circuits it — returning the cached response instead of paying for the round-trip. Provider-agnostic, so the cache spans every model behind Busbar.',
    repo: null,
    status: 'Idea',
    detail: [
      'Many requests are near-duplicates of ones you’ve already answered. Paying a provider — in latency and in dollars — to re-answer them is waste that’s hard to claw back once it’s spread across every app.',
      'Semantic Cache is a <strong>gate</strong> that recognises a request it has served before and short-circuits it, returning the cached response instead of making the round-trip. The match is semantic, not just exact-string, so close variants hit too.',
      'The cache is provider-agnostic: it spans every model behind Busbar, and it lives on the path so every app shares one cache instead of each keeping its own.',
    ],
  },
];

export const hookBySlug = (slug: string): Hook | undefined => hooks.find((h) => h.slug === slug);
