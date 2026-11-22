package goauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

const (
	methodLoginAs         = "login_as"
	codeLoginAsForbidden  = "LOGIN_AS_FORBIDDEN"
	codeLoginAsNotFound   = "LOGIN_AS_NOT_FOUND"
	codeLoginAsBadRequest = "LOGIN_AS_BAD_REQUEST"
)

// LoggedBy describes the admin (or other privileged actor) who created an
// impersonation session. It is stored on the session row and embedded in
// access / refresh JWTs as "logged_by".
type LoggedBy struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// LoginAsUser is the profile returned by LoginAsOptions.ResolveUser for both
// the actor (admin) and the target account.
type LoginAsUser struct {
	ID    string
	Name  string // full name or email shown in logged_by.name
	Email string
}

// LoginAsOptions configures the admin "login as" (impersonation) endpoint.
// Off by default.
type LoginAsOptions struct {
	// Enabled turns on GET/POST {base}/login_as. Default false.
	Enabled bool
	// Roles are the role names allowed to impersonate (for example
	// "admin", "superadmin"). Compared with GetRole (name before ":").
	// Required when Enabled is true.
	Roles []string
	// ResolveUser loads a user by id for the actor display name and to
	// confirm the target exists. Required when Enabled is true.
	ResolveUser func(ctx context.Context, userID string) (*LoginAsUser, error)
}

type loginAsFeature struct {
	enabled     bool
	roles       []string
	resolveUser func(ctx context.Context, userID string) (*LoginAsUser, error)
}

func newLoginAs(o LoginAsOptions) (*loginAsFeature, error) {
	if !o.Enabled {
		return &loginAsFeature{enabled: false}, nil
	}
	roles := make([]string, 0, len(o.Roles))
	for _, r := range o.Roles {
		r = strings.TrimSpace(r)
		if r == "" {
			continue
		}
		roles = append(roles, r)
	}
	if len(roles) == 0 {
		return nil, errors.New("LoginAs.Roles is required when LoginAs.Enabled is true")
	}
	if o.ResolveUser == nil {
		return nil, errors.New("LoginAs.ResolveUser is required when LoginAs.Enabled is true")
	}
	return &loginAsFeature{
		enabled:     true,
		roles:       roles,
		resolveUser: o.ResolveUser,
	}, nil
}

func (a *Authorization) loginAsEnabled() bool {
	return a != nil && a.loginAs != nil && a.loginAs.enabled
}

// HandleLoginAs implements GET|POST {base}/login_as?user_id=….
// The caller must already be signed in (WEB session cookie) with a role listed
// in LoginAs.Roles. On success it creates a session for the target user with
// logged_by set to the admin, issues tokens that carry the same claim, sets
// the session cookie, and renders the callback page (localStorage + redirect).
func (a *Authorization) HandleLoginAs(w http.ResponseWriter, r *http.Request) {
	if !a.loginAsEnabled() {
		notFound(w)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		w.Header().Set("Allow", "GET, POST")
		writeJSON(w, http.StatusMethodNotAllowed, Map{"code": codeBadRequest, "message": "Use GET or POST"})
		return
	}

	// login_as swaps the browser's session cookie, so another site must not
	// be able to trigger it. GET is for links inside the app: refuse it when
	// the browser says the navigation came from another site. POST needs the
	// CSRF token like every other form.
	// Only the X-Auth-Flow header skips the CSRF check: a cross-site form
	// can set a query parameter but not a custom header.
	tokenFlow := isTokenFlow(r)
	if r.Method == http.MethodGet && !sameOriginNavigation(r) {
		a.loginAsFail(w, http.StatusForbidden, codeCSRF, "Open login as from inside the app")
		return
	}
	targetID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	if r.Method == http.MethodPost {
		in, err := readForm(w, r, []CredentialField{{Name: "user_id", Type: inputText}})
		if err != nil {
			a.loginAsFail(w, http.StatusBadRequest, codeLoginAsBadRequest, err.Error())
			return
		}
		if !tokenFlow {
			_, secure, err := a.origin(r)
			if err != nil || !verifyCSRF(readCookie(r, a.jar(secure).csrfToken().Name), in.csrfToken, a.JWTSecret) {
				a.loginAsFail(w, http.StatusForbidden, codeCSRF, "Your session expired. Reload the page and try again.")
				return
			}
		}
		if targetID == "" {
			targetID = strings.TrimSpace(in.values["user_id"])
		}
	}
	if targetID == "" {
		a.loginAsFail(w, http.StatusBadRequest, codeLoginAsBadRequest, "user_id is required")
		return
	}

	session, err := a.GetSession(r.Context(), a.GetSessionID(r))
	if err != nil {
		a.loginAsFail(w, http.StatusUnauthorized, codeUnauthorized, "Sign in required")
		return
	}

	actorID := session.UserID
	if session.LoggedBy != nil && *session.LoggedBy != "" {
		// Already impersonating: privilege is checked against the original admin.
		actorID = *session.LoggedBy
	}
	actorRoles, err := a.getUserRolesFromDB(r.Context(), actorID)
	if err != nil {
		a.loginAsFail(w, http.StatusInternalServerError, codeServerError, msgSomethingWrong)
		return
	}
	has, _, _ := a.GetRole(a.loginAs.roles, FormatRoles(actorRoles))
	if !has {
		a.loginAsFail(w, http.StatusForbidden, codeLoginAsForbidden, "You are not allowed to login as another user")
		return
	}

	if targetID == actorID || targetID == session.UserID {
		a.loginAsFail(w, http.StatusBadRequest, codeLoginAsBadRequest, "Cannot login as yourself")
		return
	}

	actorProfile, err := a.loginAs.resolveUser(r.Context(), actorID)
	if err != nil {
		a.loginAsFail(w, http.StatusInternalServerError, codeServerError, msgSomethingWrong)
		return
	}
	if actorProfile == nil || actorProfile.ID == "" {
		a.loginAsFail(w, http.StatusForbidden, codeLoginAsForbidden, "You are not allowed to login as another user")
		return
	}

	target, err := a.loginAs.resolveUser(r.Context(), targetID)
	if err != nil {
		a.loginAsFail(w, http.StatusInternalServerError, codeServerError, msgSomethingWrong)
		return
	}
	if target == nil || target.ID == "" {
		a.loginAsFail(w, http.StatusNotFound, codeLoginAsNotFound, "User not found")
		return
	}

	loggedBy := &LoggedBy{
		ID:   actorProfile.ID,
		Name: cmpLoginAsName(actorProfile),
	}

	tokens, sessionID, err := a.Authorize(append(
		[]AuthorizeOptionsFunc{
			a.WithUserID(target.ID),
			a.WithLoggedBy(loggedBy),
		},
		a.SessionMetaFromRequest(r, methodLoginAs)...,
	)...)
	if err != nil {
		a.loginAsFail(w, http.StatusInternalServerError, codeServerError, msgSomethingWrong)
		return
	}

	if !tokenFlow {
		a.SetSessionIDCookie(w, r, sessionID)
		if a.keepRefreshTokenServerSide {
			tokens.RefreshToken = ""
		}
	}

	user := Map{"id": target.ID}
	if target.Name != "" {
		user["name"] = target.Name
	}
	if target.Email != "" {
		user["email"] = target.Email
	}
	payload := Map{
		payloadType:    "sign_in",
		"message":      "Signed in as " + cmpLoginAsName(target),
		"user":         user,
		"tokens":       tokens,
		"session_id":   sessionID,
		"logged_by":    loggedBy,
		"redirect_url": a.defaultRedirect(),
	}
	if tokenFlow || wantsJSON(r) {
		writeJSON(w, http.StatusOK, payload)
		return
	}
	a.renderCallbackPage(w, payload)
}

// sameOriginNavigation reports whether a GET may change the session: the
// browser says it came from this origin, or from no page at all (a typed URL
// or bookmark). Another site, including a sibling subdomain ("same-site"),
// is refused. Browsers that send no Sec-Fetch-Site header are allowed.
func sameOriginNavigation(r *http.Request) bool {
	switch strings.ToLower(r.Header.Get("Sec-Fetch-Site")) {
	case "", "same-origin", "none":
		return true
	default:
		return false
	}
}

// cmpLoginAsName returns the name shown for u: its name, email or id.
func cmpLoginAsName(u *LoginAsUser) string {
	if u == nil {
		return ""
	}
	if u.Name != "" {
		return u.Name
	}
	if u.Email != "" {
		return u.Email
	}
	return u.ID
}

func (a *Authorization) loginAsFail(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, Map{"code": code, "message": message})
}

// WithLoggedBy attaches impersonation metadata to Authorize / SignTokenPair.
func (a *Authorization) WithLoggedBy(lb *LoggedBy) AuthorizeOptionsFunc {
	return func(o *AuthorizeOptions) {
		o.loggedBy = lb
	}
}
