import {useState, type ReactNode} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import useBaseUrl from '@docusaurus/useBaseUrl';
import Layout from '@theme/Layout';
import CodeBlock from '@theme/CodeBlock';
import Heading from '@theme/Heading';

import styles from './index.module.css';

const config = `auth, err := goauth.New(&goauth.Config{
	JWTSecret:   os.Getenv("JWT_SECRET"),
	DB:          db,
	Providers:   []goauth.Provider{google.New(id, secret)},
	ResolveUser: resolveUser,
})
`;

const frameworks: {id: string; label: string; code: string}[] = [
  {
    id: 'nethttp',
    label: 'net/http',
    code: `// main.go
${config}
mux.Handle(goauth.DefaultBasePath+"/", auth.Handler())
mux.Handle("GET /api/me", auth.UseAPIAuthorization()(me))
mux.Handle("GET /dashboard", auth.UseWEBAuthorization()(dashboard))`,
  },
  {
    id: 'fiber',
    label: 'Fiber',
    code: `// main.go
${config}
app.All(goauth.DefaultBasePath+"/*", adaptor.HTTPHandler(auth.Handler()))
app.Get("/api/me", withAuth(auth.UseAPIAuthorization(), auth.GetAuthDataAPI), me)
app.Get("/dashboard", adaptor.HTTPMiddleware(auth.UseWEBAuthorization()), dashboard)`,
  },
  {
    id: 'echo',
    label: 'Echo',
    code: `// main.go
${config}
e.Any(goauth.DefaultBasePath+"/*", echo.WrapHandler(auth.Handler()))
e.GET("/api/me", me, echo.WrapMiddleware(auth.UseAPIAuthorization()))
e.GET("/dashboard", dashboard, echo.WrapMiddleware(auth.UseWEBAuthorization()))`,
  },
  {
    id: 'gin',
    label: 'Gin',
    code: `// main.go
${config}
r.Any(goauth.DefaultBasePath+"/*path", gin.WrapH(auth.Handler()))
r.GET("/api/me", wrapMiddleware(auth.UseAPIAuthorization()), me)
r.GET("/dashboard", wrapMiddleware(auth.UseWEBAuthorization()), dashboard)`,
  },
  {
    id: 'chi',
    label: 'Chi',
    code: `// main.go
${config}
r.Mount(goauth.DefaultBasePath, auth.Handler())
r.With(auth.UseAPIAuthorization()).Get("/api/me", me)
r.With(auth.UseWEBAuthorization()).Get("/dashboard", dashboard)`,
  },
];

function Hero() {
  const [active, setActive] = useState(frameworks[0].id);
  const current = frameworks.find((f) => f.id === active) ?? frameworks[0];
  return (
    <header className={styles.hero}>
      <div className={styles.stars} aria-hidden="true" />
      <div className={styles.glow} aria-hidden="true" />
      <div className={clsx('container', styles.heroInner)}>
        <div className={styles.heroText}>
          <Heading as="h1" className={styles.title}>
            goauth
          </Heading>
          <p className={styles.tagline}>Authentication for Go.</p>
          <p className={styles.tagline}>Free and open source.</p>
          <div className={styles.buttons}>
            <Link className={styles.primaryButton} to="/docs/getting-started/quick-start">
              Get Started
            </Link>
            <Link className={styles.secondaryButton} href="https://github.com/izetmolla/goauth">
              <svg viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
                <path
                  fill="currentColor"
                  d="M12 .5a11.5 11.5 0 0 0-3.64 22.41c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.37-3.88-1.37-.52-1.33-1.28-1.69-1.28-1.69-1.05-.71.08-.7.08-.7 1.16.08 1.77 1.19 1.77 1.19 1.03 1.77 2.7 1.26 3.36.96.1-.75.4-1.26.73-1.55-2.55-.29-5.24-1.28-5.24-5.68 0-1.26.45-2.28 1.19-3.09-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.17 1.18a11 11 0 0 1 5.77 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.83 1.19 3.09 0 4.41-2.69 5.39-5.25 5.67.41.36.78 1.06.78 2.14v3.17c0 .31.21.67.8.56A11.5 11.5 0 0 0 12 .5Z"
                />
              </svg>
              Source
            </Link>
          </div>
        </div>

        <div className={styles.window}>
          <div className={styles.windowBar}>
            <div className={styles.tabs} role="tablist" aria-label="Framework">
              {frameworks.map((f) => (
                <button
                  key={f.id}
                  type="button"
                  role="tab"
                  aria-selected={f.id === active}
                  className={clsx(styles.tab, f.id === active && styles.tabActive)}
                  onClick={() => setActive(f.id)}>
                  {f.label}
                </button>
              ))}
              <Link className={styles.more} to="/docs/frameworks/net-http">
                More ›
              </Link>
            </div>
            <div className={styles.dots} aria-hidden="true">
              <span style={{background: '#4ade80'}} />
              <span style={{background: '#facc15'}} />
              <span style={{background: '#f87171'}} />
            </div>
          </div>
          <div className={styles.windowCode}>
            <CodeBlock language="go">{current.code}</CodeBlock>
          </div>
        </div>
      </div>
    </header>
  );
}

type Feature = {title: string; body: ReactNode; icon: ReactNode};

const icon = (d: string) => (
  <svg viewBox="0 0 24 24" width="28" height="28" fill="none" stroke="currentColor" strokeWidth="1.8"
    strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    <path d={d} />
  </svg>
);

const features: Feature[] = [
  {
    title: 'Easy',
    icon: icon('M13 2 3 14h9l-1 8 10-12h-9l1-8Z'),
    body: (
      <>
        One <code>goauth.New</code>, one <code>auth.Handler()</code>, two middlewares. Sign-in with Google working
        in five minutes.
      </>
    ),
  },
  {
    title: 'Flexible',
    icon: icon('M4 7h16M4 12h10M4 17h6M17 14l3 3-3 3'),
    body: (
      <>
        Built on <code>net/http</code>: works with Fiber, Echo, Gin, Chi or the standard library. Any OAuth 2.0
        or OpenID Connect provider.
      </>
    ),
  },
  {
    title: 'Secure',
    icon: icon('M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Zm-3 10 2 2 4-4'),
    body: (
      <>
        PKCE, <code>state</code> and <code>nonce</code>, <code>__Host-</code> cookies, signed CSRF tokens, PBKDF2
        password hashing and revocable sessions.
      </>
    ),
  },
  {
    title: 'Your data',
    icon: icon('M4 6c0-1.7 3.6-3 8-3s8 1.3 8 3-3.6 3-8 3-8-1.3-8-3Zm0 0v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3'),
    body: (
      <>
        Users stay in your own tables. Sessions live in any GORM database, with an optional Redis cache.
      </>
    ),
  },
  {
    title: 'Roles built in',
    icon: icon('M16 11a4 4 0 1 0-8 0M4 21a8 8 0 0 1 16 0M18 4l2 2-2 2'),
    body: (
      <>
        Gate routes with <code>WithRoles</code> and read/write grants such as <code>admin:rw</code> and{' '}
        <code>hr:r</code>.
      </>
    ),
  },
  {
    title: 'Single sign-on',
    icon: icon('M3 12h4l3-8 4 16 3-8h4'),
    body: (
      <>
        Share one sign-in across <code>*.example.com</code>, link extra provider accounts, and refresh tokens from
        SPAs and mobile apps.
      </>
    ),
  },
];

function Features() {
  return (
    <section className={styles.section}>
      <div className="container">
        <div className={styles.sectionHead}>
          <Heading as="h2">Everything you need to sign users in</Heading>
          <p>Authentication and authorization for Go web apps, without giving up control of your users.</p>
        </div>
        <div className={styles.featureGrid}>
          {features.map((f) => (
            <div key={f.title} className={styles.featureCard}>
              <div className={styles.featureIcon}>{f.icon}</div>
              <Heading as="h3">{f.title}</Heading>
              <p>{f.body}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

const providers = [
  {name: 'Google', to: '/docs/providers/google', kind: 'OIDC'},
  {name: 'Azure AD / Entra ID', to: '/docs/providers/azure-ad', kind: 'OIDC'},
  {name: 'LDAP / Active Directory', to: '/docs/providers/ldap', kind: 'Directory'},
  {name: 'Email & password', to: '/docs/guides/credentials-login', kind: 'Credentials'},
  {name: 'GitHub', to: '/docs/custom-providers/examples', kind: 'OAuth 2.0'},
  {name: 'Keycloak', to: '/docs/custom-providers/examples', kind: 'OIDC'},
  {name: 'Okta / Auth0', to: '/docs/custom-providers/examples', kind: 'OIDC'},
  {name: 'Your own provider', to: '/docs/custom-providers/step-by-step', kind: 'Any'},
];

function Providers() {
  return (
    <section className={clsx(styles.section, styles.sectionAlt)}>
      <div className="container">
        <div className={styles.sectionHead}>
          <Heading as="h2">Sign in with anything</Heading>
          <p>Built-in providers, directory sign-in, passwords, and any OAuth 2.0 or OpenID Connect server.</p>
        </div>
        <div className={styles.providerGrid}>
          {providers.map((p) => (
            <Link key={p.name} to={p.to} className={styles.providerCard}>
              <span className={styles.providerName}>{p.name}</span>
              <span className={styles.providerKind}>{p.kind}</span>
            </Link>
          ))}
        </div>
      </div>
    </section>
  );
}

const steps = [
  {
    n: '1',
    title: 'Configure',
    text: 'Create one Authorization with your secret, database and providers.',
    code: `auth, _ := goauth.New(&goauth.Config{
	JWTSecret: secret,
	DB:        db,
	Providers: providers,
})`,
  },
  {
    n: '2',
    title: 'Mount',
    text: 'Serve sign-in, the OAuth callback and the provider list.',
    code: `mux.Handle(
	goauth.DefaultBasePath+"/",
	auth.Handler(),
)`,
  },
  {
    n: '3',
    title: 'Protect',
    text: 'Require a token or a session, optionally with roles.',
    code: `admin := auth.UseAPIAuthorization(
	auth.WithRoles([]string{"admin"}),
)
mux.Handle("/api/admin/", admin(api))`,
  },
];

function HowItWorks() {
  return (
    <section className={styles.section}>
      <div className="container">
        <div className={styles.sectionHead}>
          <Heading as="h2">Three steps to secure routes</Heading>
          <p>No framework to adopt, no user model to migrate to.</p>
        </div>
        <div className={styles.stepGrid}>
          {steps.map((s) => (
            <div key={s.n} className={styles.step}>
              <div className={styles.stepNumber}>{s.n}</div>
              <Heading as="h3">{s.title}</Heading>
              <p>{s.text}</p>
              <CodeBlock language="go">{s.code}</CodeBlock>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

function CallToAction() {
  const logo = useBaseUrl('/img/logo.svg');
  return (
    <section className={styles.cta}>
      <div className={styles.stars} aria-hidden="true" />
      <div className={clsx('container', styles.ctaInner)}>
        <img src={logo} alt="" width={72} height={81} />
        <Heading as="h2">Ready to add sign-in to your Go app?</Heading>
        <div className={styles.install}>
          <CodeBlock language="bash">go get github.com/izetmolla/goauth</CodeBlock>
        </div>
        <div className={styles.buttons}>
          <Link className={styles.primaryButton} to="/docs/getting-started/quick-start">
            Read the quick start
          </Link>
          <Link className={styles.secondaryButton} to="/docs/intro">
            Browse the docs
          </Link>
        </div>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={`${siteConfig.title}: ${siteConfig.tagline}`}
      description="OAuth 2.0 / OIDC sign-in, JWT tokens, database sessions and role-based access control for any Go web framework.">
      <Hero />
      <main>
        <Features />
        <Providers />
        <HowItWorks />
        <CallToAction />
      </main>
    </Layout>
  );
}
