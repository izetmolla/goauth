import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

// Ordered from first steps to advanced topics.
const sidebars: SidebarsConfig = {
  docs: [
    'intro',
    {
      type: 'category',
      label: 'Getting started',
      collapsed: false,
      items: [
        'getting-started/installation',
        'getting-started/quick-start',
        'getting-started/database-setup',
        'getting-started/core-concepts',
      ],
    },
    {
      type: 'category',
      label: 'Guides',
      collapsed: false,
      items: [
        'guides/configuration',
        'guides/endpoints',
        'guides/oauth-sign-in',
        'guides/protecting-api-routes',
        'guides/protecting-web-pages',
        'guides/roles-and-permissions',
        'guides/tokens-and-refresh',
        'guides/credentials-login',
        'guides/sign-out',
        'guides/sessions-and-redis',
        'guides/cookies',
        'guides/provider-connect',
        'guides/cross-subdomain-sso',
      ],
    },
    {
      type: 'category',
      label: 'Providers',
      items: [
        'providers/overview',
        'providers/google',
        'providers/azure-ad',
        'providers/credentials',
        'providers/ldap',
      ],
    },
    {
      type: 'category',
      label: 'Custom providers',
      items: [
        'custom-providers/overview',
        'custom-providers/step-by-step',
        'custom-providers/reusable-package',
        'custom-providers/testing',
        'custom-providers/examples',
      ],
    },
    {
      type: 'category',
      label: 'Frameworks',
      items: [
        'frameworks/net-http',
        'frameworks/fiber',
        'frameworks/echo',
        'frameworks/gin',
        'frameworks/chi',
      ],
    },
  ],
};

export default sidebars;
