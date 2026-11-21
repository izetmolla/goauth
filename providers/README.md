# goauth providers

Providers describe **how a user proves who they are**. They are registered on `goauth.Config.Providers` and served by the sign-in / callback endpoints (see the [root README](../README.md#http-endpoints)).

Presets follow the Auth.js provider set: each package exposes `New(Options)` (or a short `New(clientID, clientSecret)` for Google), a `DefaultProfile`, and documented defaults for endpoints, scopes, and checks.

## Quick start

```go
auth, err := goauth.New(&goauth.Config{
	// ...
	Providers: []goauth.Provider{
		google.New(googleClientID, googleClientSecret),
		apple.New(apple.Options{ClientID: id, ClientSecret: secret}),
		github.New(github.Options{ClientID: id, ClientSecret: secret}),
		azuread.New(azuread.Options{ClientID: id, ClientSecret: secret, TenantID: tenant}),
		auth0.New(auth0.Options{ClientID: id, ClientSecret: secret, Issuer: "https://YOUR_DOMAIN.auth0.com"}),
		credentials.New(credentials.Options{Authorize: myAuthorizeFunc}),
	},
})
```

Each provider is reachable at:

```
GET/POST /api/authorization/provider/{id}            # start sign-in
GET/POST /api/authorization/provider/{id}/callback   # OAuth callback
```

and listed by `GET /api/authorization/providers`.

## Available presets

| Provider | Package | Type | ID |
|----------|---------|------|----|
| 42 School | `providers/school42` | OAuth | `42-school` |
| Apple | `providers/apple` | OIDC | `apple` |
| Asgardeo | `providers/asgardeo` | OIDC | `asgardeo` |
| Atlassian | `providers/atlassian` | OAuth | `atlassian` |
| Auth0 | `providers/auth0` | OIDC | `auth0` |
| Authentik | `providers/authentik` | OIDC | `authentik` |
| Azure AD / Entra ID | `providers/azuread` | OIDC | `azuread-v2` |
| Azure AD B2C | `providers/azureadb2c` | OIDC | `azure-ad-b2c` |
| Azure DevOps | `providers/azuredevops` | OAuth | `azure-devops` |
| BankID Norge | `providers/bankidno` | OIDC | `bankid-no` |
| Battle.net | `providers/battlenet` | OIDC | `battlenet` |
| Beyond Identity | `providers/beyondidentity` | OIDC | `beyondidentity` |
| Bitbucket | `providers/bitbucket` | OAuth | `bitbucket` |
| Box | `providers/box` | OAuth | `box` |
| BoxyHQ SAML | `providers/boxyhqsaml` | OAuth | `boxyhq-saml` |
| Bungie | `providers/bungie` | OAuth | `bungie` |
| ClickUp | `providers/clickup` | OAuth | `click-up` |
| Cognito | `providers/cognito` | OIDC | `cognito` |
| Coinbase | `providers/coinbase` | OAuth | `coinbase` |
| Credentials | `providers/credentials` | credentials | `credentials` |
| Descope | `providers/descope` | OIDC | `descope` |
| Discord | `providers/discord` | OAuth | `discord` |
| Dribbble | `providers/dribbble` | OAuth | `dribbble` |
| Dropbox | `providers/dropbox` | OAuth | `dropbox` |
| Duende IdentityServer6 | `providers/duendeidentityserver6` | OIDC | `duende-identity-server6` |
| EVE Online | `providers/eveonline` | OAuth | `eveonline` |
| Facebook | `providers/facebook` | OAuth | `facebook` |
| Faceit | `providers/faceit` | OAuth | `faceit` |
| Figma | `providers/figma` | OAuth | `figma` |
| Foursquare | `providers/foursquare` | OAuth | `foursquare` |
| Freshbooks | `providers/freshbooks` | OAuth | `freshbooks` |
| Frontegg | `providers/frontegg` | OIDC | `frontegg` |
| FusionAuth | `providers/fusionauth` | OIDC | `fusionauth` |
| GitHub | `providers/github` | OAuth | `github` |
| GitLab | `providers/gitlab` | OAuth | `gitlab` |
| Google | `providers/google` | OIDC | `google` |
| HubSpot | `providers/hubspot` | OAuth | `hubspot` |
| IdentityServer4 | `providers/identityserver4` | OIDC | `identity-server4` |
| Instagram | `providers/instagram` | OAuth | `instagram` |
| Kakao | `providers/kakao` | OAuth | `kakao` |
| Keycloak | `providers/keycloak` | OIDC | `keycloak` |
| LINE | `providers/line` | OAuth | `line` |
| LinkedIn | `providers/linkedin` | OIDC | `linkedin` |
| Logto | `providers/logto` | OIDC | `logto` |
| Mail.ru | `providers/mailru` | OAuth | `mailru` |
| Mastodon | `providers/mastodon` | OAuth | `mastodon` |
| Mattermost | `providers/mattermost` | OAuth | `mattermost` |
| Medium | `providers/medium` | OAuth | `medium` |
| Microsoft Entra ID | `providers/microsoftentraid` | OIDC | `microsoft-entra-id` |
| Naver | `providers/naver` | OAuth | `naver` |
| Netlify | `providers/netlify` | OAuth | `netlify` |
| NetSuite | `providers/netsuite` | OAuth | `netsuite` |
| Nextcloud | `providers/nextcloud` | OAuth | `nextcloud` |
| Notion | `providers/notion` | OAuth | `notion` |
| Okta | `providers/okta` | OIDC | `okta` |
| OneLogin | `providers/onelogin` | OIDC | `onelogin` |
| Osso | `providers/osso` | OAuth | `osso` |
| osu! | `providers/osu` | OAuth | `osu` |
| Passage | `providers/passage` | OIDC | `passage` |
| Patreon | `providers/patreon` | OAuth | `patreon` |
| Pinterest | `providers/pinterest` | OAuth | `pinterest` |
| Pipedrive | `providers/pipedrive` | OAuth | `pipedrive` |
| Reddit | `providers/reddit` | OAuth | `reddit` |
| Salesforce | `providers/salesforce` | OIDC | `salesforce` |
| SimpleLogin | `providers/simplelogin` | OIDC | `simplelogin` |
| Slack | `providers/slack` | OIDC | `slack` |
| Spotify | `providers/spotify` | OAuth | `spotify` |
| Strava | `providers/strava` | OAuth | `strava` |
| Threads | `providers/threads` | OAuth | `threads` |
| TikTok | `providers/tiktok` | OAuth | `tiktok` |
| Todoist | `providers/todoist` | OAuth | `todoist` |
| Trakt | `providers/trakt` | OAuth | `trakt` |
| Twitch | `providers/twitch` | OIDC | `twitch` |
| Twitter / X | `providers/twitter` | OAuth | `twitter` |
| United Effects | `providers/unitedeffects` | OIDC | `united-effects` |
| Vipps MobilePay | `providers/vipps` | OIDC | `vipps` |
| VK | `providers/vk` | OAuth | `vk` |
| Webex | `providers/webex` | OAuth | `webex` |
| Wikimedia | `providers/wikimedia` | OAuth | `wikimedia` |
| WordPress.com | `providers/wordpress` | OAuth | `wordpress` |
| WorkOS | `providers/workos` | OAuth | `workos` |
| Yandex | `providers/yandex` | OAuth | `yandex` |
| ZITADEL | `providers/zitadel` | OIDC | `zitadel` |
| Zoho | `providers/zoho` | OAuth | `zoho` |
| Zoom | `providers/zoom` | OAuth | `zoom` |
| Passkey | `providers/passkey` | WebAuthn | `passkey` |

Detailed setup notes for a few presets:

- [google/README.md](google/README.md)
- [azuread/README.md](azuread/README.md)
- [credentials/README.md](credentials/README.md)
- [passkey/README.md](passkey/README.md)

### Not included (non-OAuth Auth.js types)

Email/magic-link providers (Nodemailer, Resend, Sendgrid, Postmark, ForwardEmail, Mailgun, Mailchimp, Loops) are not shipped yet (`ProviderEmail`).

**Passkey / WebAuthn** — [passkey/README.md](passkey/README.md) (`providers/passkey`, opt-in; adds `go-webauthn` only when imported).

## The provider model

Every provider implements the small `goauth.Provider` interface:

```go
type Provider interface {
	ID() string          // unique, URL-safe id used in routes ("google")
	Name() string        // display name ("Google")
	Type() ProviderType  // oauth | oidc | credentials | email | passkey
}
```

Concrete implementations live in the root package:

- **`goauth.OAuthProvider`** — any OAuth 2.0 / OpenID Connect service. Endpoints can be set explicitly (`AuthorizationURL`, `TokenURL`, `UserInfoURL`) or discovered from an OIDC `Issuer` (`/.well-known/openid-configuration`). Security checks (`CheckPKCE`, `CheckState`, `CheckNonce`) are opt-in per provider.
- **`goauth.CredentialsProvider`** — arbitrary credentials validated by a user-supplied `Authorize` function.

OIDC presets that need a tenant/host (Auth0, Keycloak, Okta, Cognito, …) take `Options.Issuer`. Self-hosted OAuth bases (GitLab, Mastodon, Nextcloud, WorkOS, BoxyHQ) take `Issuer` or `BaseURL`.

## From provider profile to your user

OAuth providers return a raw profile (`goauth.Profile`, a `map[string]any`). Two mapping steps run on the callback:

1. **`Provider.Profile`** (per provider) normalizes the raw payload into a `goauth.OAuthUser` (id, email, name, avatar, ...). The presets ship a sensible default.
2. **`Config.ResolveUser`** (yours, required) receives the profile — enriched with `profile["provider"]` and `profile["providerType"]` — and returns the user from **your** database (`*goauth.User` with `ID` and `Roles`). This is where you look up or provision accounts.

After `ResolveUser` succeeds, goauth creates the session, signs the token pair, sets the session cookie, and renders the callback page.

## Writing a custom OAuth/OIDC provider

No special package is needed — construct an `OAuthProvider` directly:

```go
func GitHub(clientID, clientSecret string) goauth.Provider {
	return &goauth.OAuthProvider{
		ProviderID:       "github",
		DisplayName:      "GitHub",
		Kind:             goauth.ProviderOAuth,
		ClientID:         clientID,
		ClientSecret:     clientSecret,
		AuthorizationURL: "https://github.com/login/oauth/authorize",
		TokenURL:         "https://github.com/login/oauth/access_token",
		UserInfoURL:      "https://api.github.com/user",
		Scopes:           []string{"read:user", "user:email"},
		Checks:           []goauth.Check{goauth.CheckState},
		Profile: func(p goauth.Profile, _ goauth.TokenSet) (*goauth.OAuthUser, error) {
			return &goauth.OAuthUser{
				ID:    common.String(p["id"]),
				Name:  common.String(p["name"]),
				Email: common.String(p["email"]),
				Image: common.String(p["avatar_url"]),
			}, nil
		},
	}
}
```

For OIDC services, set `Issuer` instead of the three endpoint URLs and goauth discovers them automatically.

Notes:

- `AuthorizationParams` (a `url.Values`) appends extra parameters to the authorize redirect (e.g. `prompt`, `access_type`).
- `AuthorizationStyle: "header"` sends client credentials as HTTP Basic to the token endpoint instead of in the form body.
- `UserInfoMethod: "POST"` is used when the provider’s userinfo endpoint is not GET (e.g. Dropbox).
- `FetchUserInfo` replaces the default userinfo HTTP call for providers that need a secondary API (GitHub emails, Todoist sync, VK).
- `TokenSet.Raw` preserves every non-standard field the token endpoint returned, so `Profile` can read provider-specific data.
- The `internal/common` package (`common.String`, `common.FirstNonEmpty`, `common.MapUser`, `common.DecodeIDTokenPayload`, …) is only importable by packages under `providers/`; copy the helpers if you define providers elsewhere.
