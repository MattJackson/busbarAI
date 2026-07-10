import type { APIRoute } from 'astro';
import { getCollection } from 'astro:content';

// RSS 2.0 feed for the Busbar blog, generated from the `blog` content collection.
// No @astrojs/rss dependency: the feed is a small hand-written serializer over the
// same posts src/pages/blog/* renders, so adding a post to src/content/blog/ is all
// it takes to publish it here too. Served at /rss.xml.
const SITE = 'https://getbusbar.com';
const TITLE = 'Busbar';
const DESCRIPTION =
  'Notes from Busbar on AI control-plane reliability, fidelity, and performance.';

const esc = (s: string) =>
  s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');

export const GET: APIRoute = async () => {
  const posts = (await getCollection('blog')).sort(
    (a, b) => b.data.date.valueOf() - a.data.date.valueOf(),
  );

  const items = posts
    .map((p) => {
      const link = `${SITE}/blog/${p.id}/`;
      return [
        '    <item>',
        `      <title>${esc(p.data.title)}</title>`,
        `      <link>${link}</link>`,
        `      <guid>${link}</guid>`,
        `      <pubDate>${p.data.date.toUTCString()}</pubDate>`,
        `      <description>${esc(p.data.description)}</description>`,
        '    </item>',
      ].join('\n');
    })
    .join('\n');

  const lastBuild = (posts[0]?.data.date ?? new Date()).toUTCString();

  const xml = `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
  <channel>
    <title>${esc(TITLE)}</title>
    <link>${SITE}/blog/</link>
    <description>${esc(DESCRIPTION)}</description>
    <language>en-us</language>
    <lastBuildDate>${lastBuild}</lastBuildDate>
    <atom:link href="${SITE}/rss.xml" rel="self" type="application/rss+xml" />
${items}
  </channel>
</rss>
`;

  return new Response(xml, {
    headers: { 'Content-Type': 'application/rss+xml; charset=utf-8' },
  });
};
