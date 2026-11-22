// Package passkey provides a WebAuthn / passkey provider for goauth.
//
//	import "github.com/izetmolla/goauth/providers/passkey"
//
//	passkey.New(passkey.Options{
//		RPDisplayName: "My App",
//		RPID:          "example.com",
//		RPOrigins:     []string{"https://app.example.com"},
//		Store:         myStore,
//	})
package passkey

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
	"uuid"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/izetmolla/goauth"
)

const (
	// ID is the provider id used in goauth routes: {base}/provider/passkey.
	ID             = "passkey"
	defaultName    = "Passkey"
	challengeTTL   = 5 * time.Minute
	challengePrefR = "reg:"
	challengePrefL = "login:"
)

// Credential is one passkey stored for a user.
type Credential struct {
	ID              []byte   `json:"id"`
	PublicKey       []byte   `json:"publicKey"`
	AttestationType string   `json:"attestationType,omitempty"`
	Transport       []string `json:"transport,omitempty"`
	SignCount       uint32   `json:"signCount"`
	BackupEligible  bool     `json:"backupEligible"`
	BackupState     bool     `json:"backupState"`
	UserVerified    bool     `json:"userVerified"`
	AAGUID          []byte   `json:"aaguid,omitempty"`
	Name            string   `json:"name,omitempty"`
}

// User is the passkey identity your Store returns.
type User struct {
	ID          string // your app user id (required)
	Name        string // account name / email for authenticator UI
	DisplayName string
	Handle      []byte // WebAuthn user handle; generated if empty on first register
}

// Store persists credentials and short-lived ceremony challenges.
// Implement this against your DB / Redis. MemoryStore is for tests only.
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

// Options configures the passkey provider.
type Options struct {
	ID            string
	Name          string
	RPDisplayName string
	RPID          string
	RPOrigins     []string
	Store         Store
}

// New returns a configured passkey provider. Store, RPID and RPOrigins are required.
func New(o Options) (goauth.Provider, error) {
	if o.Store == nil {
		return nil, errors.New("passkey: Store is required")
	}
	if o.RPID == "" {
		return nil, errors.New("passkey: RPID is required")
	}
	if len(o.RPOrigins) == 0 {
		return nil, errors.New("passkey: RPOrigins is required")
	}
	display := o.RPDisplayName
	if display == "" {
		display = "App"
	}
	wa, err := webauthn.New(&webauthn.Config{
		RPDisplayName: display,
		RPID:          o.RPID,
		RPOrigins:     o.RPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("passkey: webauthn: %w", err)
	}
	id := o.ID
	if id == "" {
		id = ID
	}
	name := o.Name
	if name == "" {
		name = defaultName
	}
	return &goauth.PasskeyProvider{
		ProviderID:  id,
		DisplayName: name,
		Ceremony:    &ceremony{wa: wa, store: o.Store},
	}, nil
}

type ceremony struct {
	wa    *webauthn.WebAuthn
	store Store
}

type waUser struct {
	id          string
	name        string
	displayName string
	handle      []byte
	creds       []webauthn.Credential
}

// WebAuthnID implements webauthn.User.
func (u *waUser) WebAuthnID() []byte { return u.handle }

// WebAuthnName implements webauthn.User.
func (u *waUser) WebAuthnName() string { return u.name }

// WebAuthnDisplayName implements webauthn.User.
func (u *waUser) WebAuthnDisplayName() string { return u.displayName }

// WebAuthnCredentials implements webauthn.User.
func (u *waUser) WebAuthnCredentials() []webauthn.Credential { return u.creds }

func (c *ceremony) loadUser(ctx context.Context, userID string) (*waUser, error) {
	u, err := c.store.GetUser(ctx, userID)
	if err != nil {
		return nil, err
	}
	if u == nil || u.ID == "" {
		return nil, errors.New("passkey: user not found")
	}
	handle := u.Handle
	if len(handle) == 0 {
		handle = []byte(uuid.NewV4().String())
		if err := c.store.EnsureUserHandle(ctx, u.ID, handle); err != nil {
			return nil, err
		}
	}
	name := u.Name
	if name == "" {
		name = u.ID
	}
	display := u.DisplayName
	if display == "" {
		display = name
	}
	stored, err := c.store.ListCredentials(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	creds := make([]webauthn.Credential, 0, len(stored))
	for _, s := range stored {
		creds = append(creds, toWACredential(s))
	}
	return &waUser{id: u.ID, name: name, displayName: display, handle: handle, creds: creds}, nil
}

// BeginRegister implements goauth.PasskeyCeremony.
func (c *ceremony) BeginRegister(ctx context.Context, userID, name, displayName string) (any, string, error) {
	user, err := c.loadUser(ctx, userID)
	if err != nil {
		// Allow register when Store only knows the signed-in id.
		handle := []byte(uuid.NewV4().String())
		if err := c.store.EnsureUserHandle(ctx, userID, handle); err != nil {
			return nil, "", err
		}
		if name == "" {
			name = userID
		}
		if displayName == "" {
			displayName = name
		}
		user = &waUser{id: userID, name: name, displayName: displayName, handle: handle}
	}
	creation, session, err := c.wa.BeginRegistration(user,
		webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred),
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:      protocol.ResidentKeyRequirementPreferred,
			UserVerification: protocol.VerificationPreferred,
		}),
	)
	if err != nil {
		return nil, "", err
	}
	id, err := c.putSession(ctx, challengePrefR, session)
	if err != nil {
		return nil, "", err
	}
	return creation, id, nil
}

// FinishRegister implements goauth.PasskeyCeremony.
func (c *ceremony) FinishRegister(ctx context.Context, userID, challengeID string, body io.Reader) error {
	session, err := c.takeSession(ctx, challengePrefR+challengeID)
	if err != nil {
		return err
	}
	user, err := c.loadUser(ctx, userID)
	if err != nil {
		return err
	}
	parsed, err := protocol.ParseCredentialCreationResponseBody(body)
	if err != nil {
		return err
	}
	cred, err := c.wa.CreateCredential(user, *session, parsed)
	if err != nil {
		return err
	}
	return c.store.SaveCredential(ctx, userID, fromWACredential(*cred))
}

// BeginLogin implements goauth.PasskeyCeremony.
func (c *ceremony) BeginLogin(ctx context.Context) (any, string, error) {
	assertion, session, err := c.wa.BeginDiscoverableLogin(
		webauthn.WithUserVerification(protocol.VerificationPreferred),
	)
	if err != nil {
		return nil, "", err
	}
	id, err := c.putSession(ctx, challengePrefL, session)
	if err != nil {
		return nil, "", err
	}
	return assertion, id, nil
}

// FinishLogin implements goauth.PasskeyCeremony.
func (c *ceremony) FinishLogin(ctx context.Context, challengeID string, body io.Reader) (*goauth.OAuthUser, error) {
	session, err := c.takeSession(ctx, challengePrefL+challengeID)
	if err != nil {
		return nil, err
	}
	parsed, err := protocol.ParseCredentialRequestResponseBody(body)
	if err != nil {
		return nil, err
	}
	handler := func(_, userHandle []byte) (webauthn.User, error) {
		u, err := c.store.GetUserByHandle(ctx, userHandle)
		if err != nil {
			return nil, err
		}
		if u == nil {
			return nil, errors.New("passkey: unknown user handle")
		}
		return c.loadUser(ctx, u.ID)
	}
	user, cred, err := c.wa.ValidatePasskeyLogin(handler, *session, parsed)
	if err != nil {
		return nil, err
	}
	wu, ok := user.(*waUser)
	if !ok || wu == nil {
		return nil, errors.New("passkey: invalid user")
	}
	if err := c.store.UpdateCredential(ctx, wu.id, fromWACredential(*cred)); err != nil {
		return nil, err
	}
	return &goauth.OAuthUser{
		ID:       wu.id,
		Name:     wu.displayName,
		NickName: wu.name,
		Provider: ID,
	}, nil
}

func (c *ceremony) putSession(ctx context.Context, prefix string, session *webauthn.SessionData) (string, error) {
	id := uuid.NewV4().String()
	raw, err := json.Marshal(session)
	if err != nil {
		return "", err
	}
	if err := c.store.PutChallenge(ctx, prefix+id, raw, challengeTTL); err != nil {
		return "", err
	}
	return id, nil
}

func (c *ceremony) takeSession(ctx context.Context, key string) (*webauthn.SessionData, error) {
	raw, err := c.store.TakeChallenge(ctx, key)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 {
		return nil, errors.New("passkey: challenge expired or unknown")
	}
	var session webauthn.SessionData
	if err := json.Unmarshal(raw, &session); err != nil {
		return nil, err
	}
	return &session, nil
}

func toWACredential(c Credential) webauthn.Credential {
	transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, protocol.AuthenticatorTransport(t))
	}
	return webauthn.Credential{
		ID:              c.ID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		Flags: webauthn.CredentialFlags{
			UserVerified:   c.UserVerified,
			BackupEligible: c.BackupEligible,
			BackupState:    c.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:    c.AAGUID,
			SignCount: c.SignCount,
		},
	}
}

func fromWACredential(c webauthn.Credential) Credential {
	transports := make([]string, 0, len(c.Transport))
	for _, t := range c.Transport {
		transports = append(transports, string(t))
	}
	return Credential{
		ID:              c.ID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       transports,
		SignCount:       c.Authenticator.SignCount,
		BackupEligible:  c.Flags.BackupEligible,
		BackupState:     c.Flags.BackupState,
		UserVerified:    c.Flags.UserVerified,
		AAGUID:          c.Authenticator.AAGUID,
	}
}
