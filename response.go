package goauth

import (
	"encoding/json"
	"net/http"
	"strings"
)

// Map is a shorthand for JSON object payloads, mirroring fiber.Map.
type Map map[string]any

// Machine-readable "code" values in error responses.
const (
	codeError                   = "ERROR"
	codeServerError             = "SERVER_ERROR"
	codeUnauthorized            = "UNAUTHORIZED"
	codeTokenInvalid            = "TOKEN_INVALID"
	codeInsufficientPermissions = "INSUFFICIENT_PERMISSIONS"
)

// writeError writes the {"message", "code": "ERROR"} envelope used by the
// sign-in endpoints.
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, Map{"message": message, "code": codeError})
}

// writeAPIError writes the {"error", "code"} envelope used by the middlewares.
func writeAPIError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, Map{"error": message, "code": code})
}

// writeJSON serializes v as the JSON response body with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// wantsJSON reports whether the client prefers a JSON response over a redirect.
func wantsJSON(r *http.Request) bool {
	// Match "application/json" anywhere in Accept, e.g. "application/json, text/plain".
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		return true
	}
	return r.Header.Get("X-Auth-Return-Redirect") == "1" || r.URL.Query().Get("json") == "true"
}

// redirectOrJSON either issues an HTTP redirect or returns the target URL as
// JSON, matching the Auth.js client convention (X-Auth-Return-Redirect).
func (a *Authorization) redirectOrJSON(w http.ResponseWriter, r *http.Request, target string) {
	if wantsJSON(r) {
		writeJSON(w, http.StatusOK, Map{"url": target})
		return
	}
	http.Redirect(w, r, target, http.StatusFound)
}
