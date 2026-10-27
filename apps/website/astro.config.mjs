// @ts-check
import { defineConfig } from 'astro/config';
import sitemap from '@astrojs/sitemap';
import starlight from '@astrojs/starlight';
import starlightLinksValidator from 'starlight-links-validator';
import starlightLlmsTxt from 'starlight-llms-txt';

// The public address is set at deploy time (the Cloudflare workers.dev address until the domain
// is registered, docs/09-website.md §8); local builds use the preview server.
const site = process.env.SITE_URL ?? 'http://localhost:4321';
const repo = 'https://github.com/Docker-Hunterpedia/ReverseDock';

/** @param {string} label @param {string} directory */
const section = (label, directory) => ({ label, items: [{ autogenerate: { directory: `docs/${directory}` } }] });

export default defineConfig({
  site,
  integrations: [
    starlight({
      title: 'ReverseDock',
      description: 'One reverse proxy for a laptop, a VPS, a Docker Swarm, or a Kubernetes cluster.',
      // The box is ink on light and amber on dark, where an ink box would disappear.
      logo: { light: './src/assets/logo.svg', dark: './src/assets/logo-dark.svg' },
      favicon: '/favicon.svg',
      social: [{ icon: 'github', label: 'GitHub', href: repo }],
      editLink: { baseUrl: `${repo}/edit/main/apps/website/` },
      lastUpdated: true,
      // Wrapped lines keep code blocks free of horizontal scrolling, which keyboards cannot reach.
      expressiveCode: { defaultProps: { wrap: true, preserveIndent: true } },
      customCss: ['@reversedock/harbor-tokens/tokens.css', './src/styles/starlight.css'],
      head: [
        { tag: 'link', attrs: { rel: 'icon', href: '/favicon.ico', sizes: '48x48' } },
        { tag: 'link', attrs: { rel: 'apple-touch-icon', href: '/apple-touch-icon.png' } },
        { tag: 'link', attrs: { rel: 'manifest', href: '/site.webmanifest' } },
        { tag: 'link', attrs: { rel: 'preconnect', href: 'https://fonts.googleapis.com' } },
        { tag: 'link', attrs: { rel: 'preconnect', href: 'https://fonts.gstatic.com', crossorigin: '' } },
        {
          tag: 'link',
          attrs: {
            rel: 'stylesheet',
            href: 'https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap',
          },
        },
      ],
      sidebar: [
        section('Get started', 'start'),
        section('Install', 'install'),
        section('Guides', 'guides'),
        section('Migrate', 'migrate'),
        section('Reference', 'reference'),
        section('Concepts', 'concepts'),
        section('Operations', 'operations'),
        section('Project', 'project'),
      ],
      plugins: [starlightLinksValidator(), starlightLlmsTxt({ projectName: 'ReverseDock' })],
    }),
    sitemap(),
  ],
});
