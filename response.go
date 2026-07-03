package goauth

import (
	"encoding/json"
	"net/http"
)

// Map is a shorthand for JSON object payloads, mirroring fiber.Map.
type Map map[string]any

// writeJSON serializes v as the JSON response body with the given status code.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// wantsJSON reports whether the client prefers a JSON response over a redirect.
func wantsJSON(r *http.Request) bool {
	if r.Header.Get("Accept") == "application/json" {
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
