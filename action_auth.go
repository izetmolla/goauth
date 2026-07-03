package goauth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"net/http"
	"strings"
)

func (a *Authorization) GetProviders(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		writeJSON(w, http.StatusInternalServerError, Map{
			"message": ErrNotInitialized.Error(),
			"code":    "ERROR",
		})
		return
	}
	origin, _, err := a.origin(r)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{
			"message": "Failed to get origin",
			"code":    "ERROR",
		})
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

// HandleSignIn implements {base}/signin and {base}/signin/:provider. Without a
// provider it lists providers (or redirects to a custom sign-in page). With a
// provider it initiates the appropriate flow.
func (a *Authorization) HandleSignIn(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		writeJSON(w, http.StatusInternalServerError, Map{
			"message": ErrNotInitialized.Error(),
			"code":    "ERROR",
		})
		return
	}
	origin, secure, err := a.origin(r)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{
			"message": "Failed to get origin",
			"code":    "ERROR",
		})
		return
	}
	providerID := providerIDFromRequest(r)
	p := a.findProvider(providerID)
	if p == nil {
		writeJSON(w, http.StatusOK, Map{"message": fmt.Sprintf("unknown provider: %s", providerID)})
		return
	}
	switch prov := p.(type) {
	case *OAuthProvider:
		a.startOAuth(w, r, prov, origin, secure)
	case *CredentialsProvider:
		a.credentialsCallback(w, r, prov, origin, secure)
	// case *EmailProvider:
	// 	a.startEmail(w, r, prov, origin, secure)
	// case *PasskeyProvider:
	// 	a.handlePasskeySignIn(w, r, prov)
	default:
		writeJSON(w, http.StatusBadRequest, Map{
			"message": "Unsupported provider type",
			"code":    "ERROR",
		})
	}
}

func (a *Authorization) startOAuth(w http.ResponseWriter, r *http.Request, p *OAuthProvider, origin string, secure bool) {
	ctx := r.Context()
	if err := discover(ctx, p); err != nil {
		writeJSON(w, http.StatusInternalServerError, Map{
			"message": "Discovery failed",
			"code":    "ERROR",
		})
		return
	}
	if p.AuthorizationURL == "" {
		writeJSON(w, http.StatusInternalServerError, Map{
			"message": "Provider missing AuthorizationURL",
			"code":    "ERROR",
		})
		return
	}

	jar := a.jar(secure)
	jar.expireOAuthFlowCookies(w)
	if r.URL.Query().Get("connect") == "1" {
		if err := a.SetFlowIntentCookie(w, r, FlowIntentConnect); err != nil {
			writeJSON(w, http.StatusInternalServerError, Map{
				"message": "Failed to set connect flow intent",
				"code":    "ERROR",
				"error":   err.Error(),
			})
			return
		}
		if resourceID := strings.TrimSpace(r.URL.Query().Get("resource_id")); resourceID != "" {
			if err := a.SetConnectResourceCookie(w, r, resourceID); err != nil {
				writeJSON(w, http.StatusInternalServerError, Map{
					"message": "Failed to set connect resource id",
					"code":    "ERROR",
					"error":   err.Error(),
				})
				return
			}
		}
	} else {
		expireCookie(w, jar.flowIntent())
		expireCookie(w, jar.connectResource())
	}
	cb := a.callbackURL(origin, p.ID())

	var state, verifier, nonce string
	if providerUsesCheck(p, CheckState) {
		state = randomString(32)
		setCookie(w, jar.state(), state)
	}
	if providerUsesCheck(p, CheckPKCE) {
		verifier = randomString(32)
		setCookie(w, jar.pkceCodeVerifier(), verifier)
	}
	if providerUsesCheck(p, CheckNonce) {
		nonce = randomString(32)
		setCookie(w, jar.nonce(), nonce)
	}
	if target := a.callbackTarget(r, origin); target != "" && target != origin {
		setCookie(w, jar.callbackURL(), target)
	}
	// Remember a token-flow preference so the callback (a GET from the provider)
	// can return tokens instead of a session cookie.
	if a.wantsTokens(r) { //Need to implement this
		setCookie(w, jar.flow(), "token")
	}

	target := authorizationURL(p, cb, state, verifier, nonce)
	if target == "" {
		writeJSON(w, http.StatusInternalServerError, Map{
			"message": "Failed to build authorization URL",
			"code":    "ERROR",
		})
		return
	}
	a.redirectOrJSON(w, r, target)
}

func (a *Authorization) credentialsCallback(w http.ResponseWriter, r *http.Request, p Provider, origin string, secure bool) {
	if r.Method != http.MethodPost {
		// a.writeError(w, http.StatusMethodNotAllowed, newError(KindCredentialsSignin, "credentials sign-in requires POST", nil))
		writeJSON(w, http.StatusMethodNotAllowed, Map{
			"message":  "Credentials sign-in requires POST",
			"code":     "ERROR",
			"provider": p.ID(),
			"origin":   origin,
			"secure":   secure,
		})
		return
	}
	// Token-flow (mobile/API) clients are not cookie-based, so CSRF does not
	// apply; cookie sign-in still requires the double-submit token.
	if !a.wantsTokens(r) && !a.checkCSRF(r, secure) {
		// a.writeError(w, http.StatusForbidden, newError(KindInvalidCSRF, "invalid CSRF token", nil))
		writeJSON(w, http.StatusForbidden, Map{
			"message": "Invalid CSRF token",
			"code":    "ERROR",
		})
		return
	}
	writeJSON(w, http.StatusOK, Map{
		"message": fmt.Sprintf("Working credentialsCallback() for provider %s", p.ID()),
	})
}

// HandleCallback implements {base}/callback.
// It returns a JSON response with the provider ID, origin, and secure.
// It also checks the CSRF token and returns a JSON response with the provider ID, origin, and secure.
func (a *Authorization) HandleCallback(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		writeJSON(w, http.StatusInternalServerError, Map{
			"message": ErrNotInitialized.Error(),
			"code":    "ERROR",
		})
		return
	}
	origin, secure, err := a.origin(r)
	if err != nil {
		// a.writeError(w, http.StatusBadRequest, err)
		writeJSON(w, http.StatusBadRequest, Map{
			"message": "Failed to get origin",
			"code":    "ERROR",
		})
		return
	}
	providerID := providerIDFromRequest(r)
	p := a.findProvider(providerID)
	if p == nil {
		// a.writeError(w, http.StatusNotFound, newError(KindConfiguration, "unknown provider: "+providerID, nil))
		writeJSON(w, http.StatusNotFound, Map{
			"message": fmt.Sprintf("Unknown provider: %s", providerID),
			"code":    "ERROR",
		})
		return
	}
	switch prov := p.(type) {
	case *OAuthProvider:
		a.oauthCallback(w, r, prov, origin, secure)
	case *CredentialsProvider:
		a.credentialsCallback(w, r, prov, origin, secure)
	// case *EmailProvider:
	// 	a.emailCallback(w, r, prov, origin, secure)
	// case *PasskeyProvider:
	// 	_ = r.ParseForm()
	// 	a.handlePasskeyCallback(w, r, prov, origin, secure)
	default:
		// a.writeError(w, http.StatusBadRequest, newError(KindConfiguration, "unsupported provider type", nil))
		writeJSON(w, http.StatusBadRequest, Map{
			"message": "Unsupported provider type",
			"code":    "ERROR",
		})
	}
}

func (a *Authorization) oauthCallback(w http.ResponseWriter, r *http.Request, p *OAuthProvider, origin string, secure bool) {
	ctx := r.Context()
	jar := a.jar(secure)
	defer jar.expireOAuthFlowCookies(w)

	// Some providers (notably Sign in with Apple, when name/email scopes are
	// requested) use response_mode=form_post and deliver code/state in the POST
	// body. Merge those into the query so the rest of the handler is uniform.
	q := callbackQuery(r)

	if errParam := q["error"]; errParam != "" {
		// a.failRedirect(w, r, origin, newError(KindOAuthCallback, "provider returned error: "+errParam, nil))
		a.renderCallbackPage(w, Map{
			"message": "Provider returned error",
			"code":    "ERROR",
		})
		return
	}
	code := q["code"]
	if code == "" {
		// a.failRedirect(w, r, origin, newError(KindOAuthCallback, "missing authorization code", nil))
		a.renderCallbackPage(w, Map{
			"message": "Missing authorization code",
			"code":    "ERROR",
		})
		return
	}

	// Restore a token-flow preference set during startOAuth.
	if readCookie(r, jar.flow().Name) == "token" {
		expireCookie(w, jar.flow())
		q["flow"] = "token"
	}
	if providerUsesCheck(p, CheckState) {
		expected := readCookie(r, jar.state().Name)
		expireCookie(w, jar.state())
		if expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(q["state"])) != 1 {
			// a.failRedirect(w, r, origin, newError(KindInvalidCheck, "state mismatch", nil))
			a.renderCallbackPage(w, Map{
				"message": "State mismatch",
				"code":    "ERROR",
			})
			return
		}
	}
	verifier := ""
	if providerUsesCheck(p, CheckPKCE) {
		verifier = readCookie(r, jar.pkceCodeVerifier().Name)
		expireCookie(w, jar.pkceCodeVerifier())
	}

	if err := discover(ctx, p); err != nil {
		// a.failRedirect(w, r, origin, newError(KindOAuthCallback, "discovery failed", err))
		a.renderCallbackPage(w, Map{
			"message": fmt.Sprintf("Discovery failed: %v", err),
			"code":    "ERROR",
		})
		return
	}
	cb := a.callbackURL(origin, p.ID())
	tokens, err := exchangeCode(ctx, p, code, cb, verifier)
	if err != nil {
		// a.failRedirect(w, r, origin, newError(KindOAuthCallback, "token exchange failed", err))
		a.renderCallbackPage(w, Map{
			"message": fmt.Sprintf("Token exchange failed: %v", err),
			"code":    "ERROR",
		})
		return
	}

	profile, err := fetchUserInfo(ctx, p, tokens)
	if err != nil {
		// a.failRedirect(w, r, origin, newError(KindOAuthCallback, "userinfo failed", err))
		a.renderCallbackPage(w, Map{
			"message": fmt.Sprintf("Userinfo failed: %v", err),
			"code":    "ERROR",
		})
		return
	}
	if p.Profile == nil {
		// a.failRedirect(w, r, origin, newError(KindConfiguration, "provider missing Profile function", nil))
		a.renderCallbackPage(w, Map{
			"message": "Provider missing Profile function",
			"code":    "ERROR",
		})
		return
	}
	user, err := p.Profile(profile, *tokens)
	if err != nil {
		// a.failRedirect(w, r, origin, newError(KindOAuthProfileParse, "profile mapping failed", err))
		a.renderCallbackPage(w, Map{
			"message": fmt.Sprintf("Profile mapping failed: %v", err),
			"code":    "ERROR",
		})
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
	if a.resolveUser == nil {
		a.renderCallbackPage(w, Map{
			"message": "ResolveUser() function is not set on Authorization object",
			"code":    "ERROR",
		})
		return
	}
	if profile == nil {
		profile = Profile{}
	}
	profile["provider"] = p.ID()
	profile["providerType"] = string(p.Type())
	resolvedUser, _, err := a.resolveUser(ctx, profile)
	if err != nil {
		a.renderCallbackPage(w, Map{
			"message": fmt.Sprintf("Resolve user failed: %v", err),
			"code":    "ERROR",
		})
		return
	}
	if resolvedUser == nil || resolvedUser.ID == "" {
		a.renderCallbackPage(w, Map{
			"message": "ResolveUser returned an invalid user",
			"code":    "ERROR",
		})
		return
	}

	if a.consumeFlowIntent(w, r, jar, FlowIntentConnect) {
		account.UserID = resolvedUser.ID
		a.completeProviderConnect(w, r, jar, p, resolvedUser, account)
		return
	}

	a.completeSignIn(w, r, p, resolvedUser, account)
}

func (a *Authorization) completeProviderConnect(w http.ResponseWriter, r *http.Request, jar *cookieJar, p *OAuthProvider, user *User, account *Account) {
	if user == nil || user.ID == "" {
		a.renderCallbackPage(w, Map{
			"message": "User is required to complete provider connect",
			"code":    "ERROR",
		})
		return
	}

	resourceID := a.consumeConnectResourceCookie(w, r, jar)
	if resourceID != "" && a.onProviderConnect != nil {
		if err := a.onProviderConnect(r.Context(), resourceID, account, user, p.ID()); err != nil {
			a.renderCallbackPage(w, Map{
				"message": fmt.Sprintf("Failed to save provider connect content: %v", err),
				"code":    "ERROR",
			})
			return
		}
	}

	a.renderCallbackPage(w, Map{
		"message":     "Microsoft account connected successfully.",
		"code":        "SUCCESS",
		"user":        user,
		"account":     account,
		"provider":    p.ID(),
		"type":        "connect",
		"resource_id": resourceID,
	})
}

func (a *Authorization) completeSignIn(w http.ResponseWriter, r *http.Request, p *OAuthProvider, user *User, account *Account) {
	if user == nil || user.ID == "" {
		a.renderCallbackPage(w, Map{
			"message": "User is required to complete sign-in",
			"code":    "ERROR",
		})
		return
	}

	tokens, sessionID, err := a.Authorize(append([]AuthorizeOptionsFunc{
		a.WithUserID(user.ID),
		a.WithUserRoles(user.Roles),
		a.WithAccount(account),
	}, a.SessionMetaFromRequest(r, p.ID())...)...)
	if err != nil {
		a.renderCallbackPage(w, Map{
			"message": fmt.Sprintf("Authorize failed: %v", err),
			"code":    "ERROR",
		})
		return
	}
	a.SetSessionIDCookie(w, r, sessionID)

	a.renderCallbackPage(w, Map{
		"type":       "sign_in",
		"message":    fmt.Sprintf("Successfully signed in with %s", p.ID()),
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
