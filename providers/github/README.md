# GitHub provider

GitHub OAuth for [goauth](../../README.md). When the public profile has no email, the preset also calls `/user/emails` and picks the primary address.

## Usage

```go
import "github.com/izetmolla/goauth/providers/github"

auth, err := goauth.New(&goauth.Config{
	Providers: []goauth.Provider{
		github.New(github.Options{
			ClientID:     os.Getenv("GITHUB_CLIENT_ID"),
			ClientSecret: os.Getenv("GITHUB_CLIENT_SECRET"),
		}),
	},
})
```

```
GET /api/authorization/provider/github
GET /api/authorization/provider/github/callback
```
