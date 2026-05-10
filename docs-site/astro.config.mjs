import { defineConfig } from 'astro/config';
import starlight from '@astrojs/starlight';

export default defineConfig({
  integrations: [
    starlight({
      title: {
        en: 'Wireshark MCP',
        'zh-CN': 'Wireshark MCP',
      },
      description:
        'Documentation for Wireshark MCP, a Model Context Protocol server for evidence-backed packet analysis.',
      logo: {
        src: './src/assets/logo.png',
        alt: 'Wireshark MCP',
      },
      favicon: '/logo.png',
      locales: {
        root: {
          label: 'English',
          lang: 'en',
        },
        'zh-cn': {
          label: '简体中文',
          lang: 'zh-CN',
        },
      },
      social: [
        {
          icon: 'github',
          label: 'GitHub',
          href: 'https://github.com/bx33661/Wireshark-MCP',
        },
      ],
      editLink: {
        baseUrl: 'https://github.com/bx33661/Wireshark-MCP/edit/main/docs-site/',
      },
      disable404Route: true,
      lastUpdated: true,
      customCss: ['./src/styles/custom.css'],
      sidebar: [
        {
          label: 'Start Here',
          translations: { 'zh-CN': '开始' },
          items: [
            { slug: 'getting-started/installation' },
            { slug: 'getting-started/mcp-clients' },
            { slug: 'getting-started/troubleshooting' },
            { slug: 'getting-started/deployment' },
          ],
        },
        {
          label: 'Guides',
          translations: { 'zh-CN': '使用指南' },
          items: [
            { slug: 'guides/quick-analysis' },
            { slug: 'guides/security-audit' },
            { slug: 'guides/incident-response' },
          ],
        },
        {
          label: 'Tools',
          translations: { 'zh-CN': '工具' },
          items: [
            { slug: 'tools/overview' },
            { slug: 'tools/packet-inspection' },
            { slug: 'tools/extraction-export' },
            { slug: 'tools/protocol-analysis' },
            { slug: 'tools/security-detection' },
            { slug: 'tools/statistics-visualization' },
            { slug: 'tools/capture-editing' },
          ],
        },
        {
          label: 'Reference',
          translations: { 'zh-CN': '参考' },
          items: [
            { slug: 'reference/playbooks' },
            { slug: 'reference/evidence-standard' },
            { slug: 'reference/toolchain' },
            { slug: 'reference/manual-configuration' },
            { slug: 'reference/architecture' },
            { slug: 'reference/changelog' },
          ],
        },
      ],
    }),
  ],
});
