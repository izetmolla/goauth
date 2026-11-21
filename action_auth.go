package goauth

import (
	"cmp"
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
)

// GetProviders lists the configured providers with their sign-in and
// callback URLs.
func (a *Authorization) GetProviders(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		writeError(w, http.StatusInternalServerError, ErrNotInitialized.Error())
		return
	}
	origin, _, err := a.origin(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get origin")
		return
	}
	providers := make([]PublicProvider, 0, len(a.providers))
	for _, p := range a.providers {
		if p == nil {
			continue
		}
		providers = append(providers, PublicProvider{
			ID:          p.ID(),
			Name:        p.Name(),
			Type:        string(p.Type()),
			SignInURL:   a.signInURL(origin, p.ID()),
			CallbackURL: a.callbackURL(origin, p.ID()),
		})
	}
	writeJSON(w, http.StatusOK, providers)
}

// HandleSignIn implements {base}/provider/{provider}: it starts the OAuth
// flow, or signs in directly for credentials providers.
func (a *Authorization) HandleSignIn(w http.ResponseWriter, r *http.Request) {
	a.dispatch(w, r, a.startOAuth)
}

// HandleCallback implements {base}/provider/{provider}/callback.
func (a *Authorization) HandleCallback(w http.ResponseWriter, r *http.Request) {
	a.dispatch(w, r, a.oauthCallback)
}

type oauthHandler func(w http.ResponseWriter, r *http.Request, p *OAuthProvider, origin string, secure bool)

// dispatch resolves the {provider} route parameter and hands the request to
// the handler for that provider's type.
func (a *Authorization) dispatch(w http.ResponseWriter, r *http.Request, oauth oauthHandler) {
	if a == nil {
		writeError(w, http.StatusInternalServerError, ErrNotInitialized.Error())
		return
	}
	origin, secure, err := a.origin(r)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to get origin")
		return
	}
	providerID := providerIDFromRequest(r)
	switch p := a.findProvider(providerID).(type) {
	case *OAuthProvider:
		oauth(w, r, p, origin, secure)
	case *CredentialsProvider:
		a.credentialsCallback(w, r, p)
	case *PasskeyProvider:
		writeError(w, http.StatusBadRequest, "Use /provider/"+providerID+"/(login|register)/(begin|finish) for passkeys")
	case nil:
		writeError(w, http.StatusNotFound, "Unknown provider: "+providerID)
	default:
		writeError(w, http.StatusBadRequest, "Unsupported provider type")
	}
}

func (a *Authorization) startOAuth(w http.ResponseWriter, r *http.Request, p *OAuthProvider, origin string, secure bool) {
	if err := discover(r.Context(), p); err != nil {
		writeError(w, http.StatusInternalServerError, "Discovery failed")
		return
	}
	if p.AuthorizationURL == "" {
		writeError(w, http.StatusInternalServerError, "Provider missing AuthorizationURL")
		return
	}

	jar := a.jar(secure)
	jar.expireOAuthFlowCookies(w)
	if r.URL.Query().Get("connect") == "1" {
		resourceID, err := validateConnectResourceID(r.URL.Query().Get("resource_id"))
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		// A connect flow attaches provider tokens to the signed-in user, so it
		// must start from an authenticated session.
		if err := a.startConnectIntent(w, r, jar, resourceID); err != nil {
			if errors.Is(err, ErrSessionNotFound) || errors.Is(err, ErrSessionExpired) {
				writeError(w, http.StatusUnauthorized, "Sign in before connecting an account")
				return
			}
			writeError(w, http.StatusInternalServerError, "Failed to start connect flow")
			return
		}
	} else {
		expireCookie(w, jar.flowIntent()) // connectResource is already cleared above
	}

	// newCheck issues a random value for an enabled check and stores it in its cookie.
	newCheck := func(check Check, opt CookieOption) string {
		if !providerUsesCheck(p, check) {
			return ""
		}
		v := randomString(32)
		setCookie(w, opt, v)
		return v
	}
	state := newCheck(CheckState, jar.state())
	verifier := newCheck(CheckPKCE, jar.pkceCodeVerifier())
	nonce := newCheck(CheckNonce, jar.nonce())

	if target := a.callbackTarget(r, origin); target != "" && target != origin {
		setCookie(w, jar.callbackURL(), target)
	}
	// Remember a token-flow preference so the callback (a GET from the
	// provider) can return tokens instead of a session cookie. Not yet read back.
	if a.wantsTokens(r) {
		setCookie(w, jar.flow(), "token")
	}

	target := authorizationURL(p, a.callbackURL(origin, p.ID()), state, verifier, nonce)
	if target == "" {
		writeError(w, http.StatusInternalServerError, "Failed to build authorization URL")
		return
	}
	a.redirectOrJSON(w, r, target)
}

func (a *Authorization) oauthCallback(w http.ResponseWriter, r *http.Request, p *OAuthProvider, origin string, secure bool) {
	ctx := r.Context()
	jar := a.jar(secure)
	// Flow values below are read from the request, so the response cookies can
	// be expired right away. This must happen before the page is written:
	// headers set after the body starts (e.g. from a defer) are dropped.
	jar.expireOAuthFlowCookies(w)

	if p.Profile == nil {
		a.renderCallbackError(w, "Provider missing Profile function")
		return
	}
	// Read the connect intent before anything else so the cookie is always
	// cleared, and so a stale or forged connect attempt can never fall
	// through into a sign-in.
	intent, connectUser, isConnect, err := a.consumeConnectIntent(w, r, jar)
	if err != nil {
		a.renderCallbackError(w, err.Error())
		return
	}
	if !isConnect && a.resolveUser == nil {
		a.renderCallbackError(w, "ResolveUser() function is not set on Authorization object")
		return
	}

	// Some providers (notably Sign in with Apple, when name/email scopes are
	// requested) use response_mode=form_post and deliver code/state in the POST
	// body. Merge those into the query so the rest of the handler is uniform.
	q := callbackQuery(r)
	if q["error"] != "" {
		a.renderCallbackError(w, "Provider returned error")
		return
	}
	code := q["code"]
	if code == "" {
		a.renderCallbackError(w, "Missing authorization code")
		return
	}
	if providerUsesCheck(p, CheckState) {
		expected := readCookie(r, jar.state().Name)
		if expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(q["state"])) != 1 {
			a.renderCallbackError(w, "State mismatch")
			return
		}
	}
	verifier := ""
	if providerUsesCheck(p, CheckPKCE) {
		verifier = readCookie(r, jar.pkceCodeVerifier().Name)
	}

	if err := discover(ctx, p); err != nil {
		a.renderCallbackError(w, "Discovery failed: "+err.Error())
		return
	}
	tokens, err := exchangeCode(ctx, p, code, a.callbackURL(origin, p.ID()), verifier)
	if err != nil {
		a.renderCallbackError(w, "Token exchange failed: "+err.Error())
		return
	}
	profile, err := fetchUserInfo(ctx, p, tokens)
	if err != nil {
		a.renderCallbackError(w, "Userinfo failed: "+err.Error())
		return
	}
	user, err := p.Profile(profile, *tokens)
	if err != nil {
		a.renderCallbackError(w, "Profile mapping failed: "+err.Error())
		return
	}

	account := &Account{
		Type:              string(p.Type()),
		Provider:          p.ID(),
		ProviderAccountID: user.ID,
		AccessToken:       tokens.AccessToken,
		RefreshToken:      tokens.RefreshToken,
		IDToken:           tokens.IDToken,
		TokenType:         tokens.TokenType,
		Scope:             tokens.Scope,
		ExpiresAt:         tokens.ExpiresAt(),
	}
	// A connect flow links the provider account to the user who started it
	// (bound in the signed intent), not to whoever the provider profile would
	// resolve to, so ResolveUser is not called and no user is created.
	if isConnect {
		account.UserID = connectUser.ID
		a.completeProviderConnect(w, r, p, connectUser, account, intent.ResourceID)
		return
	}

	if profile == nil {
		profile = Profile{}
	}
	profile["provider"] = p.ID()
	profile["providerType"] = string(p.Type())
	resolvedUser, _, err := a.resolveUser(ctx, profile)
	if err != nil {
		a.renderCallbackError(w, "Resolve user failed: "+err.Error())
		return
	}
	if resolvedUser == nil || resolvedUser.ID == "" {
		a.renderCallbackError(w, "ResolveUser returned an invalid user")
		return
	}
	a.completeSignIn(w, r, p, resolvedUser, account)
}

// completeProviderConnect finishes a connect flow for the signed-in user.
// The provider tokens are handed only to OnProviderConnect; they are never
// written into the callback page.
func (a *Authorization) completeProviderConnect(w http.ResponseWriter, r *http.Request, p *OAuthProvider, user *User, account *Account, resourceID string) {
	if resourceID != "" && a.onProviderConnect != nil {
		if err := a.onProviderConnect(r.Context(), resourceID, account, user, p.ID()); err != nil {
			a.renderCallbackError(w, "Failed to save provider connect content: "+err.Error())
			return
		}
	}
	a.renderCallbackPage(w, Map{
		"message":     cmp.Or(p.Name(), p.ID()) + " account connected successfully.",
		"code":        "SUCCESS",
		"provider":    p.ID(),
		payloadType:   "connect",
		"resource_id": resourceID,
	})
}

// completeSignIn creates the session; oauthCallback has already validated user.
// When TOTP MFA is enabled for the user, it returns MFA_REQUIRED instead.
func (a *Authorization) completeSignIn(w http.ResponseWriter, r *http.Request, p *OAuthProvider, user *User, account *Account) {
	if a.maybeChallengeMFA(w, r, "", user.ID, p.ID(), "", account, Map{"id": user.ID, "roles": user.Roles}) {
		return
	}
	tokens, sessionID, err := a.Authorize(append([]AuthorizeOptionsFunc{
		a.WithUserID(user.ID),
		a.WithUserRoles(user.Roles),
		a.WithAccount(account),
	}, a.SessionMetaFromRequest(r, p.ID())...)...)
	if err != nil {
		a.renderCallbackError(w, "Authorize failed: "+err.Error())
		return
	}
	a.SetSessionIDCookie(w, r, sessionID)
	if a.keepRefreshTokenServerSide {
		// The browser refreshes with the HttpOnly session cookie instead.
		tokens.RefreshToken = ""
	}
	a.renderCallbackPage(w, Map{
		payloadType:  "sign_in",
		"message":    "Successfully signed in with " + p.ID(),
		"user":       FormatUser(user),
		"tokens":     tokens,
		"session_id": sessionID,
	})
}

func (a *Authorization) WithUserID(userID string) AuthorizeOptionsFunc {
	return func(o *AuthorizeOptions) {
		o.userID = userID
	}
}
func (a *Authorization) WithUserRoles(roles JSONBArray) AuthorizeOptionsFunc {
	return func(o *AuthorizeOptions) {
		o.roles = roles
	}
}

func (a *Authorization) WithAccount(account *Account) AuthorizeOptionsFunc {
	return func(o *AuthorizeOptions) {
		o.account = account
	}
}

func (a *Authorization) WithContext(ctx context.Context) AuthorizeOptionsFunc {
	return func(o *AuthorizeOptions) {
		if ctx != nil {
			o.ctx = ctx
		}
	}
}

func (a *Authorization) WithIPAddress(ipAddress string) AuthorizeOptionsFunc {
	return func(o *AuthorizeOptions) {
		o.ipAddress = ipAddress
	}
}

func (a *Authorization) WithUserAgent(userAgent string) AuthorizeOptionsFunc {
	return func(o *AuthorizeOptions) {
		o.userAgent = userAgent
	}
}

func (a *Authorization) WithMethod(method string) AuthorizeOptionsFunc {
	return func(o *AuthorizeOptions) {
		if method != "" {
			o.method = method
		}
	}
}

// SessionMetaFromRequest captures request metadata stored on the session row.
func (a *Authorization) SessionMetaFromRequest(r *http.Request, method string) []AuthorizeOptionsFunc {
	return []AuthorizeOptionsFunc{
		a.WithContext(r.Context()),
		a.WithIPAddress(clientIP(r)),
		a.WithUserAgent(r.UserAgent()),
		a.WithMethod(method),
	}
}
