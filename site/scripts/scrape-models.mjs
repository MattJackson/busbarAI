// Refreshes src/models.json — the config builder's model catalog.
//
// Seed source: models.dev (open, CC-licensed catalog that tracks REAL per-provider
// wire IDs — unlike aggregator slugs, these are the ids each provider's own API
// accepts). Run manually when refreshing the builder's list, review the diff,
// commit the result. Never a runtime dependency: the site serves the committed
// snapshot only.
//
//   node scripts/scrape-models.mjs
import { readFileSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const here = dirname(fileURLToPath(import.meta.url));

// models.dev provider id -> busbar providers.yaml catalog name.
// Only providers present in the shipped catalog appear here.
const MAP = {
  anthropic: 'anthropic',
  openai: 'openai',
  google: 'gemini',
  'amazon-bedrock': 'bedrock',
  cohere: 'cohere',
  deepseek: 'deepseek',
  mistral: 'mistral',
  xai: 'xai',
  groq: 'groq',
  togetherai: 'together',
  'fireworks-ai': 'fireworks',
  moonshotai: 'moonshot',
  alibaba: 'dashscope',
  zai: 'zai-api',
  minimax: 'minimax',
  deepinfra: 'deepinfra',
  cerebras: 'cerebras',
  nvidia: 'nvidia-nim',
  nebius: 'nebius',
  baseten: 'baseten',
  chutes: 'chutes',
  openrouter: 'openrouter',
  'novita-ai': 'novita',
  friendli: 'friendliai',
  scaleway: 'scaleway',
  ovhcloud: 'ovhcloud',
  gmicloud: 'gmi',
  sarvam: 'sarvam',
  'nano-gpt': 'nano-gpt',
  synthetic: 'synthetic',
  wandb: 'wandb',
  llama: 'meta-llama',
  // promoted to the verified catalog 2026-07-09 (docs-verified, wave 1)
  digitalocean: 'digitalocean',
  'github-models': 'github-models',
  huggingface: 'huggingface',
  siliconflow: 'siliconflow',
  upstage: 'upstage',
  stepfun: 'stepfun',
  zhipuai: 'zhipuai',
  xiaomi: 'xiaomi',
  vultr: 'vultr',
  'ollama-cloud': 'ollama-cloud',
  inception: 'inception',
  morph: 'morph',
  longcat: 'longcat',
  sakana: 'sakana',
  nearai: 'nearai',
  // promoted to the verified catalog 2026-07-09 (docs-verified, wave 2)
  '302ai': '302ai',
  abacus: 'abacus',
  'abliteration-ai': 'abliteration-ai',
  ambient: 'ambient',
  anyapi: 'anyapi',
  auriko: 'auriko',
  bailing: 'bailing',
  berget: 'berget',
  clarifai: 'clarifai',
  claudinio: 'claudinio',
  'cloudferro-sherlock': 'cloudferro-sherlock',
  cortecs: 'cortecs',
  crof: 'crof',
  crossmodel: 'crossmodel',
  dinference: 'dinference',
  drun: 'drun',
  evroc: 'evroc',
  fastrouter: 'fastrouter',
  frogbot: 'frogbot',
  helicone: 'helicone',
  'hpc-ai': 'hpc-ai',
  iflowcn: 'iflowcn',
  inceptron: 'inceptron',
  inference: 'inference',
  'io-net': 'io-net',
  jiekou: 'jiekou',
  kenari: 'kenari',
  kilo: 'kilo',
  lilac: 'lilac',
  llmgateway: 'llmgateway',
  llmtr: 'llmtr',
  meganova: 'meganova',
  mixlayer: 'mixlayer',
  moark: 'moark',
  modelscope: 'modelscope',
  neuralwatt: 'neuralwatt',
  opencode: 'opencode',
  'opencode-go': 'opencode-go',
  orcarouter: 'orcarouter',
  poe: 'poe',
  'qihang-ai': 'qihang-ai',
  'qiniu-ai': 'qiniu-ai',
  'regolo-ai': 'regolo-ai',
  requesty: 'requesty',
  stackit: 'stackit',
  'stepfun-ai': 'stepfun-ai',
  submodel: 'submodel',
  'tencent-tokenhub': 'tencent-tokenhub',
  'the-grid-ai': 'the-grid-ai',
  tinfoil: 'tinfoil',
  trustedrouter: 'trustedrouter',
  'umans-ai': 'umans-ai',
  'wafer.ai': 'wafer.ai',
  xpersona: 'xpersona',
  zeldoc: 'zeldoc',
  zenifra: 'zenifra',
  zenmux: 'zenmux',
};

const res = await fetch('https://models.dev/api.json');
if (!res.ok) throw new Error(`models.dev fetch failed: ${res.status}`);
const catalog = await res.json();

const providers = {};
let total = 0;
for (const [mdId, busbarName] of Object.entries(MAP)) {
  const p = catalog[mdId];
  if (!p) { console.warn(`models.dev id missing: ${mdId}`); continue; }
  // newest first (the builder's "popular" list takes each major provider's newest),
  // then slim to the fields the page renders — keeps the inlined payload small.
  const models = Object.values(p.models)
    .sort((a, b) => String(b.release_date ?? '').localeCompare(String(a.release_date ?? '')) || String(a.id).localeCompare(String(b.id)))
    .map((m) => ({ id: m.id, name: m.name || m.id, ctx: m.limit?.context ?? null }));
  providers[busbarName] = {
    label: p.name || busbarName,
    env: Array.isArray(p.env) && p.env.length ? p.env[0] : null,
    models,
  };
  total += models.length;
}

// Every shipped-catalog provider is selectable in the builder, even the ones
// models.dev doesn't track (empty model list = free-text ids only). The builder
// must never offer a provider the catalog can't serve, and never hide one it can.
// Each provider also carries its REAL catalog entry (base_url, error_map) so the
// builder can emit a complete, working providers.yaml alongside config.yaml.
const catalogYaml = readFileSync(join(here, '..', '..', 'providers.yaml'), 'utf8');
const heads = [...catalogYaml.matchAll(/^([a-z0-9._-]+):.*$/gm)];
const entryFor = {};
for (let i = 0; i < heads.length; i++) {
  const start = heads[i].index;
  const end = i + 1 < heads.length ? heads[i + 1].index : catalogYaml.length;
  // trim trailing blank lines and any section-banner comments belonging to the NEXT entry
  const block = catalogYaml.slice(start, end).split('\n')
    .filter((l, idx, arr) => !(l.startsWith('#') || (l.trim() === '' && arr.slice(idx).every((r) => r.startsWith('#') || r.trim() === ''))))
    .join('\n').trimEnd();
  entryFor[heads[i][1]] = block;
}
const catalogNames = heads.map((m) => m[1]);
for (const name of catalogNames) {
  if (!providers[name]) providers[name] = { label: name, env: null, models: [] };
  providers[name].yaml = entryFor[name] || null;
}
for (const name of Object.keys(providers)) {
  if (!catalogNames.includes(name)) console.warn(`builder provider not in shipped catalog: ${name}`);
}

// Tier 2 — GENERATED entries: every models.dev provider that (a) declares itself
// OpenAI-compatible, (b) publishes an API base URL, and (c) isn't already covered
// by the verified catalog. Busbar speaks the language, so these work — but their
// error-code dialects are unmapped, and the generated yaml says so.
const mapped = new Set(Object.keys(MAP));
// Providers verified DEAD or unshippable - never offer them, even generated.
// lambda: Inference API discontinued ~Sep 2025, api.lambda.ai is NXDOMAIN.
// github-copilot: no public completion API; token exchange + ToS forbid gateway use.
const DEAD = new Set(['lambda', 'github-copilot']);
let gen = 0;
// Regional/plan variants (alibaba-cn, xiaomi-token-plan-ams, *-coding-plan, …) are
// distinct endpoints but pure noise in a picker; the plain provider represents them.
const VARIANT = /-(cn|coding-plan|token-plan)(-|$)|-token-plan$/;
for (const [mdId, p] of Object.entries(catalog)) {
  if (mapped.has(mdId) || providers[mdId] || DEAD.has(mdId)) continue;
  if (VARIANT.test(mdId)) continue;
  if (p.npm !== '@ai-sdk/openai-compatible' || !p.api) continue;
  const models = Object.values(p.models || {});
  if (!models.length) continue;
  // busbar's openai protocol appends /v1/chat/completions to base_url; normalize:
  // trailing /v1 strips cleanly, any other path prefix keeps a `path` override.
  const api = p.api.replace(/\/+$/, '');
  let entry;
  if (api.endsWith('/v1')) {
    entry = `${mdId}:\n  protocol: openai\n  base_url: ${api.slice(0, -3).replace(/\/+$/, '')}`;
  } else if (new URL(api).pathname !== '/') {
    entry = `${mdId}:\n  protocol: openai\n  base_url: ${api}\n  path: /chat/completions`;
  } else {
    entry = `${mdId}:\n  protocol: openai\n  base_url: ${api}`;
  }
  providers[mdId] = {
    label: p.name || mdId,
    env: Array.isArray(p.env) && p.env.length ? p.env[0] : null,
    gen: true,
    yaml: `# GENERATED from models.dev - not in the verified catalog. The endpoint shape is\n# inferred; verify it, and note error-code dialects are unmapped (HTTP-status\n# classification still applies). Verified catalog: https://getbusbar.com/providers.yaml\n${entry}`,
    models: models
      .sort((a, b) => String(b.release_date ?? '').localeCompare(String(a.release_date ?? '')) || String(a.id).localeCompare(String(b.id)))
      .map((m) => ({ id: m.id, name: m.name || m.id, ctx: m.limit?.context ?? null })),
  };
  gen++; total += providers[mdId].models.length;
}
console.log(`tier 2 (generated, openai-compatible): ${gen} providers`);

const out = {
  source: 'models.dev (snapshot; refreshed manually via scripts/scrape-models.mjs)',
  providers,
};

writeFileSync(join(here, '..', 'src', 'models.json'), JSON.stringify(out) + '\n');
console.log(`wrote src/models.json: ${Object.keys(providers).length} providers, ${total} models`);
