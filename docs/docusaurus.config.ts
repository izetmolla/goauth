import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

// This runs in Node.js - Don't use client-side code here (browser APIs, JSX...)

const author = 'Izet Molla';
const repo = 'https://github.com/izetmolla/goauth';

const config: Config = {
  title: 'goauth',
  tagline: 'Framework-agnostic authentication and authorization for Go',
  favicon: 'img/favicon.svg',

  future: {
    v4: true,
  },

  url: 'https://goauth.izetmolla.com',
  baseUrl: '/',
  organizationName: 'izetmolla',
  projectName: 'goauth',
  trailingSlash: false,

  onBrokenLinks: 'throw',
  markdown: {
    hooks: {
      onBrokenMarkdownLinks: 'throw',
    },
  },

  headTags: [
    {tagName: 'meta', attributes: {name: 'author', content: author}},
  ],

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: `${repo}/tree/main/docs/`,
          showLastUpdateAuthor: false,
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  themes: [
    [
      // Offline, self-hosted full-text search: the index is built at
      // `pnpm build` time, so no external service (Algolia) is needed.
      '@easyops-cn/docusaurus-search-local',
      {
        hashed: true,
        indexDocs: true,
        indexPages: true,
        indexBlog: false,
        docsRouteBasePath: '/docs',
        language: ['en'],
        highlightSearchTermsOnTargetPage: true,
        explicitSearchResultPath: true,
        searchBarShortcutHint: true,
      },
    ],
  ],

  themeConfig: {
    image: 'img/goauth-logo.png',
    colorMode: {
      respectPrefersColorScheme: true,
    },
    navbar: {
      title: 'goauth',
      logo: {
        alt: 'goauth logo',
        src: 'img/logo.svg',
      },
      items: [
        {type: 'docSidebar', sidebarId: 'docs', position: 'left', label: 'Docs'},
        {to: '/docs/frameworks/net-http', label: 'Frameworks', position: 'left'},
        {type: 'search', position: 'right'},
        {href: 'https://pkg.go.dev/github.com/izetmolla/goauth', label: 'pkg.go.dev', position: 'right'},
        {href: repo, label: 'GitHub', position: 'right'},
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Learn',
          items: [
            {label: 'Introduction', to: '/docs/intro'},
            {label: 'Quick start', to: '/docs/getting-started/quick-start'},
            {label: 'Core concepts', to: '/docs/getting-started/core-concepts'},
          ],
        },
        {
          title: 'Frameworks',
          items: [
            {label: 'net/http', to: '/docs/frameworks/net-http'},
            {label: 'Fiber', to: '/docs/frameworks/fiber'},
            {label: 'Echo', to: '/docs/frameworks/echo'},
            {label: 'Gin', to: '/docs/frameworks/gin'},
            {label: 'Chi', to: '/docs/frameworks/chi'},
          ],
        },
        {
          title: 'More',
          items: [
            {label: 'GitHub', href: repo},
            {label: 'pkg.go.dev', href: 'https://pkg.go.dev/github.com/izetmolla/goauth'},
            {label: 'Releases', href: `${repo}/tags`},
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} ${author}. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['go', 'bash', 'sql', 'json', 'yaml', 'nginx', 'docker'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
