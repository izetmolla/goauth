package goauth

import (
	"context"
	"crypto/subtle"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v3"
)

func (a *Authorization) GetProviders(c fiber.Ctx) error {
	if a == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": ErrNotInitialized.Error(),
			"code":    "ERROR",
		})
	}
	origin, _, err := a.origin(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to get origin",
			"code":    "ERROR",
		})
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
	return c.JSON(providers)
}

// handleSignIn implements {base}/signin and {base}/signin/:provider. Without a
// provider it lists providers (or redirects to a custom sign-in page). With a
// provider it initiates the appropriate flow.
func (a *Authorization) HandleSignIn(c fiber.Ctx) error {
	if a == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": ErrNotInitialized.Error(),
			"code":    "ERROR",
		})
	}
	origin, secure, err := a.origin(c)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to get origin",
			"code":    "ERROR",
		})
	}
	providerID := c.Params("provider")
	p := a.findProvider(providerID)
	if p == nil {
		return c.JSON(fiber.Map{"message": fmt.Sprintf("unknown provider: %s", providerID)})
	}
	switch prov := p.(type) {
	case *OAuthProvider:
		return a.startOAuth(c, prov, origin, secure)
	case *CredentialsProvider:
		return a.credentialsCallback(c, prov, origin, secure)
	// case *EmailProvider:
	// 	a.startEmail(w, r, prov, origin, secure)
	// case *PasskeyProvider:
	// 	a.handlePasskeySignIn(w, r, prov)
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Unsupported provider type",
			"code":    "ERROR",
		})
	}
}

func (a *Authorization) startOAuth(c fiber.Ctx, p *OAuthProvider, origin string, secure bool) error {
	ctx := c.Context()
	if err := discover(ctx, p); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Discovery failed",
			"code":    "ERROR",
		})
	}
	if p.AuthorizationURL == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Provider missing AuthorizationURL",
			"code":    "ERROR",
		})
	}

	jar := a.jar(secure)
	jar.expireOAuthFlowCookies(c)
	if c.Query("connect") == "1" {
		if err := a.SetFlowIntentCookie(c, FlowIntentConnect); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"message": "Failed to set connect flow intent",
				"code":    "ERROR",
				"error":   err.Error(),
			})
		}
		if resourceID := strings.TrimSpace(c.Query("resource_id")); resourceID != "" {
			if err := a.SetConnectResourceCookie(c, resourceID); err != nil {
				return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
					"message": "Failed to set connect resource id",
					"code":    "ERROR",
					"error":   err.Error(),
				})
			}
		}
	} else {
		expireCookie(c, jar.flowIntent())
		expireCookie(c, jar.connectResource())
	}
	cb := a.callbackURL(origin, p.ID())

	var state, verifier, nonce string
	if providerUsesCheck(p, CheckState) {
		state = randomString(32)
		setCookie(c, jar.state(), state)
	}
	if providerUsesCheck(p, CheckPKCE) {
		verifier = randomString(32)
		setCookie(c, jar.pkceCodeVerifier(), verifier)
	}
	if providerUsesCheck(p, CheckNonce) {
		nonce = randomString(32)
		setCookie(c, jar.nonce(), nonce)
	}
	if target := a.callbackTarget(c, origin); target != "" && target != origin {
		setCookie(c, jar.callbackURL(), target)
	}
	// Remember a token-flow preference so the callback (a GET from the provider)
	// can return tokens instead of a session cookie.
	if a.wantsTokens(c) { //Need to implement this
		setCookie(c, jar.flow(), "token")
	}

	// a.redirectOrJSON(w, r, authorizationURL(p, cb, state, verifier, nonce))

	// return c.JSON(fiber.Map{
	// 	"message":  fmt.Sprintf("Working startOAuth() for provider %s", p.ID()),
	// 	"origin":   origin,
	// 	"secure":   secure,
	// 	"jar":      jar,
	// 	"cb":       cb,
	// 	"state":    state,
	// 	"verifier": verifier,
	// 	"nonce":    nonce,
	// })
	target := authorizationURL(p, cb, state, verifier, nonce)
	if target == "" {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": "Failed to build authorization URL",
			"code":    "ERROR",
		})
	}
	return a.redirectOrJSON(c, target)
}

func (a *Authorization) credentialsCallback(c fiber.Ctx, p Provider, origin string, secure bool) error {
	if c.Method() != fiber.MethodPost {
		// a.writeError(w, http.StatusMethodNotAllowed, newError(KindCredentialsSignin, "credentials sign-in requires POST", nil))
		return c.Status(fiber.StatusMethodNotAllowed).JSON(fiber.Map{
			"message":  "Credentials sign-in requires POST",
			"code":     "ERROR",
			"provider": p.ID(),
			"origin":   origin,
			"secure":   secure,
		})
	}
	// Token-flow (mobile/API) clients are not cookie-based, so CSRF does not
	// apply; cookie sign-in still requires the double-submit token.
	if !a.wantsTokens(c) && !a.checkCSRF(c, secure) {
		// a.writeError(w, http.StatusForbidden, newError(KindInvalidCSRF, "invalid CSRF token", nil))
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"message": "Invalid CSRF token",
			"code":    "ERROR",
		})
	}
	return c.JSON(fiber.Map{
		"message": fmt.Sprintf("Working credentialsCallback() for provider %s", p.ID()),
	})
}

// HandleCallback implements {base}/callback.
// It returns a JSON response with the provider ID, origin, and secure.
// It also checks the CSRF token and returns a JSON response with the provider ID, origin, and secure.
func (a *Authorization) HandleCallback(c fiber.Ctx) error {
	if a == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"message": ErrNotInitialized.Error(),
			"code":    "ERROR",
		})
	}
	origin, secure, err := a.origin(c)
	if err != nil {
		// a.writeError(w, http.StatusBadRequest, err)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Failed to get origin",
			"code":    "ERROR",
		})
	}
	providerID := c.Params("provider")
	p := a.findProvider(providerID)
	if p == nil {
		// a.writeError(w, http.StatusNotFound, newError(KindConfiguration, "unknown provider: "+providerID, nil))
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"message": fmt.Sprintf("Unknown provider: %s", providerID),
			"code":    "ERROR",
		})
	}
	switch prov := p.(type) {
	case *OAuthProvider:
		return a.oauthCallback(c, prov, origin, secure)
	case *CredentialsProvider:
		return a.credentialsCallback(c, prov, origin, secure)
	// case *EmailProvider:
	// 	a.emailCallback(w, r, prov, origin, secure)
	// case *PasskeyProvider:
	// 	_ = r.ParseForm()
	// 	a.handlePasskeyCallback(w, r, prov, origin, secure)
	default:
		// a.writeError(w, http.StatusBadRequest, newError(KindConfiguration, "unsupported provider type", nil))
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Unsupported provider type",
			"code":    "ERROR",
		})
	}
}

func (a *Authorization) oauthCallback(c fiber.Ctx, p *OAuthProvider, origin string, secure bool) error {
	ctx := c.Context()
	jar := a.jar(secure)
	defer jar.expireOAuthFlowCookies(c)

	// Some providers (notably Sign in with Apple, when name/email scopes are
	// requested) use response_mode=form_post and deliver code/state in the POST
	// body. Merge those into the query so the rest of the handler is uniform.
	q := callbackQuery(c)

	if errParam := q["error"]; errParam != "" {
		// a.failRedirect(w, r, origin, newError(KindOAuthCallback, "provider returned error: "+errParam, nil))
		return a.renderCallbackPage(c, fiber.Map{
			"message": "Provider returned error",
			"code":    "ERROR",
		})
	}
	code := q["code"]
	if code == "" {
		// a.failRedirect(w, r, origin, newError(KindOAuthCallback, "missing authorization code", nil))
		return a.renderCallbackPage(c, fiber.Map{
			"message": "Missing authorization code",
			"code":    "ERROR",
		})
	}

	// Restore a token-flow preference set during startOAuth.
	if readCookie(c, jar.flow().Name) == "token" {
		expireCookie(c, jar.flow())
		q["flow"] = "token"
	}
	if providerUsesCheck(p, CheckState) {
		expected := readCookie(c, jar.state().Name)
		expireCookie(c, jar.state())
		if expected == "" || subtle.ConstantTimeCompare([]byte(expected), []byte(q["state"])) != 1 {
			// a.failRedirect(w, r, origin, newError(KindInvalidCheck, "state mismatch", nil))
			return a.renderCallbackPage(c, fiber.Map{
				"message": "State mismatch",
				"code":    "ERROR",
			})
		}
	}
	verifier := ""
	if providerUsesCheck(p, CheckPKCE) {
		verifier = readCookie(c, jar.pkceCodeVerifier().Name)
		expireCookie(c, jar.pkceCodeVerifier())
	}

	if err := discover(ctx, p); err != nil {
		// a.failRedirect(w, r, origin, newError(KindOAuthCallback, "discovery failed", err))
		return a.renderCallbackPage(c, fiber.Map{
			"message": fmt.Sprintf("Discovery failed: %v", err),
			"code":    "ERROR",
		})
	}
	cb := a.callbackURL(origin, p.ID())
	tokens, err := exchangeCode(ctx, p, code, cb, verifier)
	if err != nil {
		// a.failRedirect(w, r, origin, newError(KindOAuthCallback, "token exchange failed", err))
		return a.renderCallbackPage(c, fiber.Map{
			"message": fmt.Sprintf("Token exchange failed: %v", err),
			"code":    "ERROR",
		})
	}

	profile, err := fetchUserInfo(ctx, p, tokens)
	if err != nil {
		// a.failRedirect(w, r, origin, newError(KindOAuthCallback, "userinfo failed", err))
		return a.renderCallbackPage(c, fiber.Map{
			"message": fmt.Sprintf("Userinfo failed: %v", err),
			"code":    "ERROR",
		})
	}
	if p.Profile == nil {
		// a.failRedirect(w, r, origin, newError(KindConfiguration, "provider missing Profile function", nil))
		return a.renderCallbackPage(c, fiber.Map{
			"message": "Provider missing Profile function",
			"code":    "ERROR",
		})
	}
	user, err := p.Profile(profile, *tokens)
	if err != nil {
		// a.failRedirect(w, r, origin, newError(KindOAuthProfileParse, "profile mapping failed", err))
		return a.renderCallbackPage(c, fiber.Map{
			"message": fmt.Sprintf("Profile mapping failed: %v", err),
			"code":    "ERROR",
		})
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
		return a.renderCallbackPage(c, fiber.Map{
			"message": "ResolveUser() function is not set on Authorization object",
			"code":    "ERROR",
		})
	}
	if profile == nil {
		profile = Profile{}
	}
	profile["provider"] = p.ID()
	profile["providerType"] = string(p.Type())
	resolvedUser, _, err := a.resolveUser(ctx, profile)
	if err != nil {
		return a.renderCallbackPage(c, fiber.Map{
			"message": fmt.Sprintf("Resolve user failed: %v", err),
			"code":    "ERROR",
		})
	}
	if resolvedUser == nil || resolvedUser.ID == "" {
		return a.renderCallbackPage(c, fiber.Map{
			"message": "ResolveUser returned an invalid user",
			"code":    "ERROR",
		})
	}

	if a.consumeFlowIntent(c, jar, FlowIntentConnect) {
		account.UserID = resolvedUser.ID
		return a.completeProviderConnect(c, jar, p, resolvedUser, account)
	}

	return a.completeSignIn(c, p, resolvedUser, account)
}

func (a *Authorization) completeProviderConnect(c fiber.Ctx, jar *cookieJar, p *OAuthProvider, user *User, account *Account) error {
	if user == nil || user.ID == "" {
		return a.renderCallbackPage(c, fiber.Map{
			"message": "User is required to complete provider connect",
			"code":    "ERROR",
		})
	}

	resourceID := a.consumeConnectResourceCookie(c, jar)
	if resourceID != "" && a.onProviderConnect != nil {
		if err := a.onProviderConnect(c.Context(), resourceID, account, user, p.ID()); err != nil {
			return a.renderCallbackPage(c, fiber.Map{
				"message": fmt.Sprintf("Failed to save provider connect content: %v", err),
				"code":    "ERROR",
			})
		}
	}

	return a.renderCallbackPage(c, fiber.Map{
		"message":     "Microsoft account connected successfully.",
		"code":        "SUCCESS",
		"user":        user,
		"account":     account,
		"provider":    p.ID(),
		"type":        "connect",
		"resource_id": resourceID,
	})
}

func (a *Authorization) completeSignIn(c fiber.Ctx, p *OAuthProvider, user *User, account *Account) error {
	if user == nil || user.ID == "" {
		return a.renderCallbackPage(c, fiber.Map{
			"message": "User is required to complete sign-in",
			"code":    "ERROR",
		})
	}

	tokens, session_id, err := a.Authorize(append([]AuthorizeOptionsFunc{
		a.WithUserID(user.ID),
		a.WithUserRoles(user.Roles),
		a.WithAccount(account),
	}, a.SessionMetaFromRequest(c, p.ID())...)...)
	if err != nil {
		return a.renderCallbackPage(c, fiber.Map{
			"message": fmt.Sprintf("Authorize failed: %v", err),
			"code":    "ERROR",
		})
	}
	a.SetSessionIDCookie(c, session_id)

	return a.renderCallbackPage(c, fiber.Map{
		"type":       "sign_in",
		"message":    fmt.Sprintf("Successfully signed in with %s", p.ID()),
		"user":       FormatUser(user),
		"tokens":     tokens,
		"session_id": session_id,
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
func (a *Authorization) SessionMetaFromRequest(c fiber.Ctx, method string) []AuthorizeOptionsFunc {
	return []AuthorizeOptionsFunc{
		a.WithContext(c.Context()),
		a.WithIPAddress(c.IP()),
		a.WithUserAgent(c.UserAgent()),
		a.WithMethod(method),
	}
}
