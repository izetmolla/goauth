// Package credentials provides a username/password (or any custom fields)
// provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/credentials"
//
//	credentials.New(credentials.Options{ Authorize: ... })
package credentials

import (
	"context"

	"github.com/gofiber/fiber/v3"
	"github.com/izetmolla/goauth"
)

// Options configures a credentials provider.
type Options struct {
	ID        string
	Name      string
	Fields    []goauth.CredentialField
	Authorize func(ctx context.Context, credentials map[string]string, c fiber.Ctx) (*goauth.User, error)
}

// New builds a credentials provider. Authorize is required. Credentials sessions
// always use the JWT strategy.
func New(o Options) goauth.Provider {
	id := o.ID
	if id == "" {
		id = "credentials"
	}
	name := o.Name
	if name == "" {
		name = "Credentials"
	}
	return &goauth.CredentialsProvider{
		ProviderID:  id,
		DisplayName: name,
		Fields:      o.Fields,
		// Authorize:   o.Authorize,
	}
}
