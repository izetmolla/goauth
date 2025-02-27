package azuread

import (
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/izetmolla/goauth"
)

// Session is the implementation of `goauth.Session` for accessing AzureAD.
type Session struct {
	AuthURL      string
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// GetAuthURL will return the URL set by calling the `BeginAuth` function on the Facebook provider.
func (s Session) GetAuthURL() (string, error) {
	if s.AuthURL == "" {
		return "", errors.New(goauth.NoAuthUrlErrorMessage)
	}

	return s.AuthURL, nil
}

// Authorize the session with AzureAD and return the access token to be stored for future use.
func (s *Session) Authorize(provider goauth.Provider, params goauth.Params) (string, error) {
	p := provider.(*Provider)
	token, err := p.config.Exchange(goauth.ContextForClient(p.Client()), params.Get("code"))
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
	session := &Session{}
	err := json.NewDecoder(strings.NewReader(data)).Decode(session)
	return session, err
}
