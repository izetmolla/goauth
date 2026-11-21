# Passkey provider

WebAuthn / passkey sign-in for [goauth](../../README.md), powered by [`go-webauthn`](https://github.com/go-webauthn/webauthn).

Importing this package pulls in WebAuthn dependencies. Apps that never import `providers/passkey` do **not** link that code into their binary.

## Usage

```go
import (
	"github.com/izetmolla/goauth"
	"github.com/izetmolla/goauth/providers/passkey"
)

store := /* your Store implementation */

pk, err := passkey.New(passkey.Options{
	RPDisplayName: "My App",
	RPID:          "example.com", // use "localhost" for local HTTP
	RPOrigins:     []string{"https://app.example.com"},
	Store:         store,
})
if err != nil {
	log.Fatal(err)
}

auth, err := goauth.New(&goauth.Config{
	// ...
	Providers: []goauth.Provider{pk},
})
```

### Options

| Field | Required | Description |
|-------|----------|-------------|
| `Store` | yes | Persist credentials + ceremony challenges (see below) |
| `RPID` | yes | Relying-party ID (`example.com` or `localhost`) |
| `RPOrigins` | yes | Allowed browser origins for ceremonies |
| `RPDisplayName` | no | Shown by the authenticator UI (default `App`) |
| `ID` / `Name` | no | Defaults to `passkey` / `Passkey` |

## Endpoints

Prefix = `goauth.DefaultBasePath` (`/api/authorization`):

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| `POST` | `/provider/passkey/register/begin` | signed-in session or JWT | Creation options + `challengeId` |
| `POST` | `/provider/passkey/register/finish` | signed-in | Verify attestation, store credential |
| `POST` | `/provider/passkey/login/begin` | public | Discoverable-login options + `challengeId` |
| `POST` | `/provider/passkey/login/finish` | public | Verify assertion → session / tokens |

`GET /provider/passkey` is not used; clients must call the begin/finish URLs.

### Begin response

```json
{
  "options": { "...": "PublicKeyCredentialCreationOptions or RequestOptions" },
  "publicKey": { "...": "same as options (client alias)" },
  "challengeId": "uuid"
}
```

### Finish request

Send the WebAuthn credential JSON, and echo the challenge id either as:

- header `X-Passkey-Challenge: <challengeId>`, or
- JSON envelope:

```json
{
  "challengeId": "uuid",
  "credential": { "id": "...", "rawId": "...", "type": "public-key", "response": { } }
}
```

On successful **login/finish**, the response matches credentials/OAuth sign-in (`tokens`, `session_id`, callback page, or JSON for `Accept: application/json` / `X-Auth-Flow: token`).

## Client flow

**Register** (user already signed in):

1. `POST .../register/begin`
2. `navigator.credentials.create({ publicKey: body.options.publicKey ?? body.options })`
3. `POST .../register/finish` with `challengeId` + credential

**Sign in** (discoverable / usernameless):

1. `POST .../login/begin`
2. `navigator.credentials.get({ publicKey: body.options.publicKey ?? body.options })`
3. `POST .../login/finish` with `challengeId` + credential

## Store interface

You must implement `passkey.Store` against your database (and usually Redis for challenges):

```go
type Store interface {
	GetUser(ctx context.Context, userID string) (*User, error)
	GetUserByHandle(ctx context.Context, handle []byte) (*User, error)
	EnsureUserHandle(ctx context.Context, userID string, handle []byte) error
	ListCredentials(ctx context.Context, userID string) ([]Credential, error)
	SaveCredential(ctx context.Context, userID string, cred Credential) error
	UpdateCredential(ctx context.Context, userID string, cred Credential) error
	PutChallenge(ctx context.Context, id string, data []byte, ttl time.Duration) error
	TakeChallenge(ctx context.Context, id string) ([]byte, error)
}
```

Suggested columns for credentials: `credential_id`, `user_id`, `public_key`, `sign_count`, `transports`, `backup_*`, `aaguid`.

`passkey.NewMemoryStore()` is for **tests / demos only**.

## Dev notes

- HTTPS is required in browsers except for `localhost`.
- Changing `RPID` invalidates existing credentials for that RP.
- WebAuthn deps are only linked if you import this package.

## Related

- [providers/README.md](../README.md)
- [credentials/README.md](../credentials/README.md)
- [Auth.js Passkey](https://authjs.dev/getting-started/providers/passkey)
