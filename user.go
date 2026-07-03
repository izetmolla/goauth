package goauth

import (
	"context"
	"encoding/gob"
	"errors"
	"net/http"
	"time"
)

func init() {
	gob.Register(OAuthUser{})
}

type User struct {
	ID      string     `json:"id"`
	Roles   JSONBArray `json:"roles"`
	Content JSONBAny   `json:"content"`
	User    JSONBAny   `json:"user" gorm:"-"`
}

// User contains the information common amongst most OAuth and OAuth2 providers.
// All the "raw" data from the provider can be found in the `RawData` field.
type OAuthUser struct {
	ID                string
	RawData           map[string]any
	Provider          string
	Email             string
	Name              string
	FirstName         string
	LastName          string
	NickName          string
	Description       string
	UserID            string
	AvatarURL         string
	Location          string
	AccessToken       string
	AccessTokenSecret string
	RefreshToken      string
	ExpiresAt         time.Time
	IDToken           string
	Image             string
}

func (d *Authorization) getUserRolesFromDB(ctx context.Context, userID string) (JSONBArray, error) {
	if d == nil || d.db == nil {
		return nil, errors.New("db manager is not initialized")
	}
	if userID == "" {
		return nil, errors.New("user ID cannot be empty")
	}
	var user User
	err := d.db.WithContext(ctx).
		Table(d.userTableName).
		Select("roles").
		Where("id = ?", userID).
		First(&user).Error
	if err != nil {
		return nil, err
	}
	if len(user.Roles) == 0 {
		return JSONBArray([]any{}), nil
	}
	return user.Roles, nil
}

// AuthData is the authenticated principal extracted from either a JWT
// (API requests) or a session cookie (WEB requests).
type AuthData struct {
	SessionID string
	UserID    string
	Roles     []string
}

// User returns the authenticated principal for the current request.
// Pass fromAPI=true to read it out of the JWT instead of the session
// cookie. The variadic shape preserves the original ergonomic API.
func (a *Authorization) User(r *http.Request, reqCtx context.Context, fromAPI ...bool) (*AuthData, error) {
	useAPI := len(fromAPI) > 0 && fromAPI[0]
	var (
		data AuthData
		err  error
	)
	if useAPI {
		data, err = a.GetAuthDataAPI(r)
	} else {
		data, err = a.GetAuthDataWEB(r, reqCtx)
	}
	if err != nil {
		return nil, err
	}
	return &data, nil
}

// GetAuthDataAPI extracts the authenticated principal from a JWT-protected
// request.
func (a *Authorization) GetAuthDataAPI(r *http.Request) (AuthData, error) {
	claims, err := a.GetClaims(r)
	if err != nil {
		return AuthData{}, err
	}
	data := AuthData{
		SessionID: stringClaim(claims, "session_id"),
		UserID:    stringClaim(claims, "user_id"),
	}
	if roles, err := a.GetRoles(r); err == nil {
		data.Roles = roles
	} else {
		data.Roles = []string{}
	}
	return data, nil
}

// GetAuthDataWEB extracts the authenticated principal from a
// cookie-protected request by loading the matching session row.
func (a *Authorization) GetAuthDataWEB(r *http.Request, reqCtx context.Context) (AuthData, error) {
	session, err := a.GetSession(reqCtx, a.GetSessionID(r))
	if err != nil {
		return AuthData{}, err
	}
	return AuthData{
		SessionID: session.ID,
		UserID:    session.UserID,
		Roles:     FormatRoles(session.User.Roles),
	}, nil
}
