---
title: Preset catalog
description: Usage pages for every OAuth / OIDC provider preset shipped with goauth.
sidebar_position: 0
---

# All provider presets

Each preset lives under `github.com/izetmolla/goauth/providers/<package>` and is registered on `Config.Providers`.

Redirect URI for every OAuth/OIDC preset:

```text
https://YOUR_APP/api/authorization/provider/{id}/callback
```

Also see: [Credentials](../credentials.md) · [Passkey](../passkey.md) · [Google (detailed)](../google.md) · [Azure AD (detailed)](../azure-ad.md)

| Provider | Package | id | Type | Docs |
|---|---|---|---|---|
| 42 School | `providers/school42` | `42-school` | `oauth` | [school42](./school42.md) |
| Apple | `providers/apple` | `apple` | `oidc` | [apple](./apple.md) |
| Asgardeo | `providers/asgardeo` | `asgardeo` | `oidc` | [asgardeo](./asgardeo.md) |
| Atlassian | `providers/atlassian` | `atlassian` | `oauth` | [atlassian](./atlassian.md) |
| Auth0 | `providers/auth0` | `auth0` | `oidc` | [auth0](./auth0.md) |
| Authentik | `providers/authentik` | `authentik` | `oidc` | [authentik](./authentik.md) |
| Azure Active Directory | `providers/azuread` | `azuread-v2` | `oidc` | [azuread](./azuread.md) |
| Azure AD B2C | `providers/azureadb2c` | `azure-ad-b2c` | `oidc` | [azureadb2c](./azureadb2c.md) |
| Azure DevOps | `providers/azuredevops` | `azure-devops` | `oauth` | [azuredevops](./azuredevops.md) |
| BankID Norge | `providers/bankidno` | `bankid-no` | `oidc` | [bankidno](./bankidno.md) |
| Battle.net | `providers/battlenet` | `battlenet` | `oidc` | [battlenet](./battlenet.md) |
| Beyond Identity | `providers/beyondidentity` | `beyondidentity` | `oidc` | [beyondidentity](./beyondidentity.md) |
| Bitbucket | `providers/bitbucket` | `bitbucket` | `oauth` | [bitbucket](./bitbucket.md) |
| Box | `providers/box` | `box` | `oauth` | [box](./box.md) |
| BoxyHQ SAML | `providers/boxyhqsaml` | `boxyhq-saml` | `oauth` | [boxyhqsaml](./boxyhqsaml.md) |
| Bungie | `providers/bungie` | `bungie` | `oauth` | [bungie](./bungie.md) |
| ClickUp | `providers/clickup` | `click-up` | `oauth` | [clickup](./clickup.md) |
| Cognito | `providers/cognito` | `cognito` | `oidc` | [cognito](./cognito.md) |
| Coinbase | `providers/coinbase` | `coinbase` | `oauth` | [coinbase](./coinbase.md) |
| Descope | `providers/descope` | `descope` | `oidc` | [descope](./descope.md) |
| Discord | `providers/discord` | `discord` | `oauth` | [discord](./discord.md) |
| Dribbble | `providers/dribbble` | `dribbble` | `oauth` | [dribbble](./dribbble.md) |
| Dropbox | `providers/dropbox` | `dropbox` | `oauth` | [dropbox](./dropbox.md) |
| Duende IdentityServer6 | `providers/duendeidentityserver6` | `duende-identity-server6` | `oidc` | [duendeidentityserver6](./duendeidentityserver6.md) |
| EVE Online | `providers/eveonline` | `eveonline` | `oauth` | [eveonline](./eveonline.md) |
| Facebook | `providers/facebook` | `facebook` | `oauth` | [facebook](./facebook.md) |
| Faceit | `providers/faceit` | `faceit` | `oauth` | [faceit](./faceit.md) |
| Figma | `providers/figma` | `figma` | `oauth` | [figma](./figma.md) |
| Foursquare | `providers/foursquare` | `foursquare` | `oauth` | [foursquare](./foursquare.md) |
| Freshbooks | `providers/freshbooks` | `freshbooks` | `oauth` | [freshbooks](./freshbooks.md) |
| Frontegg | `providers/frontegg` | `frontegg` | `oidc` | [frontegg](./frontegg.md) |
| FusionAuth | `providers/fusionauth` | `fusionauth` | `oidc` | [fusionauth](./fusionauth.md) |
| GitHub | `providers/github` | `github` | `oauth` | [github](./github.md) |
| GitLab | `providers/gitlab` | `gitlab` | `oauth` | [gitlab](./gitlab.md) |
| Google | `providers/google` | `google` | `oidc` | [google](./google.md) |
| HubSpot | `providers/hubspot` | `hubspot` | `oauth` | [hubspot](./hubspot.md) |
| IdentityServer4 | `providers/identityserver4` | `identity-server4` | `oidc` | [identityserver4](./identityserver4.md) |
| Instagram | `providers/instagram` | `instagram` | `oauth` | [instagram](./instagram.md) |
| Kakao | `providers/kakao` | `kakao` | `oauth` | [kakao](./kakao.md) |
| Keycloak | `providers/keycloak` | `keycloak` | `oidc` | [keycloak](./keycloak.md) |
| LINE | `providers/line` | `line` | `oauth` | [line](./line.md) |
| LinkedIn | `providers/linkedin` | `linkedin` | `oidc` | [linkedin](./linkedin.md) |
| Logto | `providers/logto` | `logto` | `oidc` | [logto](./logto.md) |
| Mail.ru | `providers/mailru` | `mailru` | `oauth` | [mailru](./mailru.md) |
| Mastodon | `providers/mastodon` | `mastodon` | `oauth` | [mastodon](./mastodon.md) |
| Mattermost | `providers/mattermost` | `mattermost` | `oauth` | [mattermost](./mattermost.md) |
| Medium | `providers/medium` | `medium` | `oauth` | [medium](./medium.md) |
| Microsoft Entra ID | `providers/microsoftentraid` | `microsoft-entra-id` | `oidc` | [microsoftentraid](./microsoftentraid.md) |
| Naver | `providers/naver` | `naver` | `oauth` | [naver](./naver.md) |
| Netlify | `providers/netlify` | `netlify` | `oauth` | [netlify](./netlify.md) |
| NetSuite | `providers/netsuite` | `netsuite` | `oauth` | [netsuite](./netsuite.md) |
| Nextcloud | `providers/nextcloud` | `nextcloud` | `oauth` | [nextcloud](./nextcloud.md) |
| Notion | `providers/notion` | `notion` | `oauth` | [notion](./notion.md) |
| Okta | `providers/okta` | `okta` | `oidc` | [okta](./okta.md) |
| OneLogin | `providers/onelogin` | `onelogin` | `oidc` | [onelogin](./onelogin.md) |
| Osso | `providers/osso` | `osso` | `oauth` | [osso](./osso.md) |
| osu! | `providers/osu` | `osu` | `oauth` | [osu](./osu.md) |
| Passage | `providers/passage` | `passage` | `oidc` | [passage](./passage.md) |
| Patreon | `providers/patreon` | `patreon` | `oauth` | [patreon](./patreon.md) |
| Pinterest | `providers/pinterest` | `pinterest` | `oauth` | [pinterest](./pinterest.md) |
| Pipedrive | `providers/pipedrive` | `pipedrive` | `oauth` | [pipedrive](./pipedrive.md) |
| Reddit | `providers/reddit` | `reddit` | `oauth` | [reddit](./reddit.md) |
| Salesforce | `providers/salesforce` | `salesforce` | `oidc` | [salesforce](./salesforce.md) |
| SimpleLogin | `providers/simplelogin` | `simplelogin` | `oidc` | [simplelogin](./simplelogin.md) |
| Slack | `providers/slack` | `slack` | `oidc` | [slack](./slack.md) |
| Spotify | `providers/spotify` | `spotify` | `oauth` | [spotify](./spotify.md) |
| Strava | `providers/strava` | `strava` | `oauth` | [strava](./strava.md) |
| Threads | `providers/threads` | `threads` | `oauth` | [threads](./threads.md) |
| TikTok | `providers/tiktok` | `tiktok` | `oauth` | [tiktok](./tiktok.md) |
| Todoist | `providers/todoist` | `todoist` | `oauth` | [todoist](./todoist.md) |
| Trakt | `providers/trakt` | `trakt` | `oauth` | [trakt](./trakt.md) |
| Twitch | `providers/twitch` | `twitch` | `oidc` | [twitch](./twitch.md) |
| Twitter | `providers/twitter` | `twitter` | `oauth` | [twitter](./twitter.md) |
| United Effects | `providers/unitedeffects` | `united-effects` | `oidc` | [unitedeffects](./unitedeffects.md) |
| Vipps MobilePay | `providers/vipps` | `vipps` | `oidc` | [vipps](./vipps.md) |
| VK | `providers/vk` | `vk` | `oauth` | [vk](./vk.md) |
| Webex | `providers/webex` | `webex` | `oauth` | [webex](./webex.md) |
| Wikimedia | `providers/wikimedia` | `wikimedia` | `oauth` | [wikimedia](./wikimedia.md) |
| WordPress.com | `providers/wordpress` | `wordpress` | `oauth` | [wordpress](./wordpress.md) |
| WorkOS | `providers/workos` | `workos` | `oauth` | [workos](./workos.md) |
| Yandex | `providers/yandex` | `yandex` | `oauth` | [yandex](./yandex.md) |
| ZITADEL | `providers/zitadel` | `zitadel` | `oidc` | [zitadel](./zitadel.md) |
| Zoho | `providers/zoho` | `zoho` | `oauth` | [zoho](./zoho.md) |
| Zoom | `providers/zoom` | `zoom` | `oauth` | [zoom](./zoom.md) |

_84 presets._
