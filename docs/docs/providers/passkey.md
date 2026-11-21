---
title: Passkey / WebAuthn
description: Opt-in passkey provider for passwordless sign-in with WebAuthn authenticators.
---

# Passkey / WebAuthn

The `providers/passkey` package adds WebAuthn (passkeys, security keys, platform authenticators) to goauth.

Importing it pulls in [`go-webauthn`](https://github.com/go-webauthn/webauthn). Apps that never import the package do **not** link that dependency.

This is separate from [Authenticator MFA (TOTP)](../guides/mfa-totp.md). Passkeys can be a primary sign-in method; TOTP is a second factor after another method succeeds.

## Install and register

```go
import (
	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/passkey"
)

pk, err := passkey.New(passkey.Options{
	RPDisplayName: "My App",
	RPID:          "example.com", // "localhost" for local HTTP
	RPOrigins:     []string{"https://app.example.com"},
	Store:         myStore, // you implement Store
})
if err != nil {
	log.Fatal(err)
}

auth, err := goauth.New(&goauth.Config{
	JWTSecret: secret,
	DB:        db,
	Providers: []goauth.Provider{pk},
	ResolveUser: resolveUser, // used after login/finish
})
```

### Options

| Field | Required | Description |
|---|---|---|
| `Store` | yes | Persist credentials and ceremony challenges |
| `RPID` | yes | Relying-party ID (`example.com` or `localhost`) |
| `RPOrigins` | yes | Allowed browser origins |
| `RPDisplayName` | no | Shown by the authenticator UI (default `App`) |
| `ID` / `Name` | no | Defaults to `passkey` / `Passkey` |

## Endpoints

Under `{base}` (`/api/authorization` by default):

| Method | Path | Auth | Purpose |
|---|---|---|---|
| `POST` | `/provider/passkey/register/begin` | signed-in | Creation options + `challengeId` |
| `POST` | `/provider/passkey/register/finish` | signed-in | Verify attestation, store credential |
| `POST` | `/provider/passkey/login/begin` | public | Discoverable-login options + `challengeId` |
| `POST` | `/provider/passkey/login/finish` | public | Verify assertion → session / tokens |

`GET /provider/passkey` is not used for sign-in.

### Begin response

```json
{
  "options": { },
  "publicKey": { },
  "challengeId": "uuid"
}
```

### Finish request

Send the WebAuthn credential JSON and echo `challengeId` as header `X-Passkey-Challenge` or in a JSON envelope:

```json
{
  "challengeId": "uuid",
  "credential": { "id": "...", "rawId": "...", "type": "public-key", "response": { } }
}
```

Successful **login/finish** matches other goauth sign-ins (tokens, session cookie, callback page, or JSON). If [TOTP MFA](../guides/mfa-totp.md) is enabled for that user, you get `MFA_REQUIRED` instead of a session until `/mfa/totp/verify` succeeds.

## Store interface

You own persistence. A typical layout:

- **Credentials**: credential id, user id, public key, sign count, transports, …
- **Challenges**: short-lived ceremony state keyed by `challengeId`

See [`providers/passkey/README.md`](https://github.com/izetmolla/goauth/tree/main/providers/passkey) for `Store`, `MemoryStore` (tests only), and field details.

## Browser flow (sketch)

1. `POST .../login/begin` → pass `publicKey` to `navigator.credentials.get(...)`.
2. `POST .../login/finish` with the assertion + `challengeId`.
3. Persist tokens / session like any other goauth sign-in.

Registration is the same pattern with `create` / `register/*` while the user is already signed in.
