package goauth

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
)

const (
	maxPasskeyBody       = 256 << 10
	passkeyChallengeHdr  = "X-Passkey-Challenge"
	passkeyChallengeJSON = "challengeId"
)

// passkeyAction is the trailing path segment under /provider/{id}/...
type passkeyAction string

const (
	passkeyRegisterBegin  passkeyAction = "register/begin"
	passkeyRegisterFinish passkeyAction = "register/finish"
	passkeyLoginBegin     passkeyAction = "login/begin"
	passkeyLoginFinish    passkeyAction = "login/finish"
)

// HandlePasskey serves POST /provider/{passkey}/(register|login)/(begin|finish).
func (a *Authorization) HandlePasskey(w http.ResponseWriter, r *http.Request) {
	if a == nil {
		writeError(w, http.StatusInternalServerError, ErrNotInitialized.Error())
		return
	}
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", http.MethodPost)
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	p, ok := a.findProvider(providerIDFromRequest(r)).(*PasskeyProvider)
	if !ok || p.Ceremony == nil {
		writeError(w, http.StatusNotFound, "Unknown provider: "+providerIDFromRequest(r))
		return
	}
	action := passkeyActionFromRequest(r)
	switch action {
	case passkeyRegisterBegin:
		a.passkeyRegisterBegin(w, r, p)
	case passkeyRegisterFinish:
		a.passkeyRegisterFinish(w, r, p)
	case passkeyLoginBegin:
		a.passkeyLoginBegin(w, r, p)
	case passkeyLoginFinish:
		a.passkeyLoginFinish(w, r, p)
	default:
		writeError(w, http.StatusNotFound, "Unknown passkey action")
	}
}

func passkeyActionFromRequest(r *http.Request) passkeyAction {
	// Prefer Go 1.22+ wildcards if registered as .../{action...}
	if v := r.PathValue("action"); v != "" {
		return passkeyAction(strings.Trim(v, "/"))
	}
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	// .../provider/{id}/register/begin
	for i, part := range parts {
		if part == "provider" && i+3 < len(parts) {
			return passkeyAction(parts[i+2] + "/" + parts[i+3])
		}
	}
	return ""
}

func (a *Authorization) passkeyRegisterBegin(w http.ResponseWriter, r *http.Request, p *PasskeyProvider) {
	auth, err := a.currentPasskeyUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Sign in before registering a passkey")
		return
	}
	name := auth.UserID
	display := auth.UserID
	options, challengeID, err := p.Ceremony.BeginRegister(r.Context(), auth.UserID, name, display)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not start passkey registration")
		return
	}
	writeJSON(w, http.StatusOK, Map{
		"options":            options,
		passkeyChallengeJSON: challengeID,
		"publicKey":          options, // alias used by some clients
	})
}

func (a *Authorization) passkeyRegisterFinish(w http.ResponseWriter, r *http.Request, p *PasskeyProvider) {
	auth, err := a.currentPasskeyUser(r)
	if err != nil {
		writeError(w, http.StatusUnauthorized, "Sign in before registering a passkey")
		return
	}
	challengeID, body, err := readPasskeyFinish(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := p.Ceremony.FinishRegister(r.Context(), auth.UserID, challengeID, body); err != nil {
		writeError(w, http.StatusBadRequest, "Passkey registration failed")
		return
	}
	writeJSON(w, http.StatusOK, Map{"ok": true, "message": "Passkey registered"})
}

func (a *Authorization) passkeyLoginBegin(w http.ResponseWriter, r *http.Request, p *PasskeyProvider) {
	options, challengeID, err := p.Ceremony.BeginLogin(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Could not start passkey sign-in")
		return
	}
	writeJSON(w, http.StatusOK, Map{
		"options":            options,
		passkeyChallengeJSON: challengeID,
		"publicKey":          options,
	})
}

func (a *Authorization) passkeyLoginFinish(w http.ResponseWriter, r *http.Request, p *PasskeyProvider) {
	challengeID, body, err := readPasskeyFinish(w, r)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	user, err := p.Ceremony.FinishLogin(r.Context(), challengeID, body)
	if err != nil || user == nil || user.ID == "" {
		writeError(w, http.StatusUnauthorized, "Passkey sign-in failed")
		return
	}
	if user.Provider == "" {
		user.Provider = p.ID()
	}
	a.finishSignIn(w, r, pageSignIn, user.ID, publicUser(user), p.ID(), "")
}

func (a *Authorization) currentPasskeyUser(r *http.Request) (*AuthData, error) {
	// Prefer cookie session; fall back to JWT context when API middleware ran.
	if data, err := a.User(r, r.Context()); err == nil && data != nil && data.UserID != "" {
		return data, nil
	}
	if data, err := a.User(r, r.Context(), true); err == nil && data != nil && data.UserID != "" {
		return data, nil
	}
	return nil, errors.New("unauthorized")
}

func readPasskeyFinish(w http.ResponseWriter, r *http.Request) (challengeID string, body io.Reader, err error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxPasskeyBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return "", nil, errors.New("invalid body")
	}
	challengeID = strings.TrimSpace(r.Header.Get(passkeyChallengeHdr))
	if challengeID == "" {
		var envelope struct {
			ChallengeID string          `json:"challengeId"`
			Credential  json.RawMessage `json:"credential"`
			Response    json.RawMessage `json:"response"`
		}
		if json.Unmarshal(raw, &envelope) == nil {
			challengeID = strings.TrimSpace(envelope.ChallengeID)
			if len(envelope.Credential) > 0 {
				raw = envelope.Credential
			} else if len(envelope.Response) > 0 {
				raw = envelope.Response
			}
		}
	}
	if challengeID == "" {
		return "", nil, errors.New("missing challengeId")
	}
	return challengeID, bytes.NewReader(raw), nil
}
