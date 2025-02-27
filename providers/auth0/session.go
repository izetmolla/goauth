package auth0

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/izetmolla/goauth"
)

// Session stores data during the auth process with Auth0.
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

var _ goauth.Session = &Session{}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Auth0 provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goauth.NoAuthUrlErrorMessage)
	}
	return s.AuthURL, nil
}

// Authorize the session with Auth0 and return the access token to be stored for future use.
func (s *Session) Authorize(provider goauth.Provider, params goauth.Params) (string, error) {
	ctx := context.Background()
	p := provider.(*Provider)
	token, err := p.config.Exchange(ctx, params.Get("code"))
	if err != nil {
		return "", err
	}

	if !token.Valid() {
		return "", errors.New("invalid token received from provider")
	}

	s.AccessToken = token.AccessToken
	s.RefreshToken = token.RefreshToken
	s.ExpiresAt = token.Expiry
	return token.AccessToken, err
}

// Marshal the session into a string
func (s Session) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s Session) String() string {
	return s.Marshal()
}

// UnmarshalSession wil unmarshal a JSON string into a session.
func (p *Provider) UnmarshalSession(data string) (goauth.Session, error) {
	s := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(s)
	return s, err
}
