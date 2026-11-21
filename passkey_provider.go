package goauth

import (
	"context"
	"io"
)

// PasskeyCeremony is the WebAuthn begin/finish surface implemented by
// providers/passkey. Keeping it as an interface means the core package does
// not import go-webauthn; only apps that register a passkey provider pull that
// dependency into their binary.
type PasskeyCeremony interface {
	// BeginRegister returns PublicKeyCredentialCreationOptions and a
	// challenge id the client must echo on FinishRegister.
	BeginRegister(ctx context.Context, userID, name, displayName string) (options any, challengeID string, err error)
	// FinishRegister verifies the attestation and persists the credential.
	FinishRegister(ctx context.Context, userID, challengeID string, body io.Reader) error
	// BeginLogin returns PublicKeyCredentialRequestOptions for a discoverable
	// (usernameless) passkey assertion.
	BeginLogin(ctx context.Context) (options any, challengeID string, err error)
	// FinishLogin verifies the assertion and returns the signed-in user.
	FinishLogin(ctx context.Context, challengeID string, body io.Reader) (*OAuthUser, error)
}

// PasskeyProvider is a WebAuthn / passkey sign-in provider.
type PasskeyProvider struct {
	ProviderID  string
	DisplayName string
	// Ceremony performs the WebAuthn steps. Required.
	Ceremony PasskeyCeremony
}

func (p *PasskeyProvider) ID() string         { return p.ProviderID }
func (p *PasskeyProvider) Name() string       { return p.DisplayName }
func (p *PasskeyProvider) Type() ProviderType { return ProviderPasskey }
