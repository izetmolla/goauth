package goauth

import (
	"cmp"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"html/template"
	"io/fs"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"
)

// uiFiles holds the built-in sign-in page: an HTML template plus the CSS
// and JS it loads. They are compiled into the binary, so the page needs no
// files on disk and no external requests.
//
//go:embed ui
var uiFiles embed.FS

var (
	// sessionJS is shared by the sign-in page (as an asset) and the OAuth
	// callback page (inlined), so both store sessions in the same format.
	sessionJS = template.JS(mustReadUI("ui/session.js"))

	uiAssets, uiAssetVersion = loadUIAssets()
)

func mustReadUI(name string) []byte {
	b, err := uiFiles.ReadFile(name)
	if err != nil {
		panic(err)
	}
	return b
}

type uiAsset struct {
	body        []byte
	contentType string
	etag        string
}

// loadUIAssets indexes the servable CSS/JS files and derives one version
// hash from their contents. Asset URLs carry ?v=<hash>, so browsers can
// cache them forever and still pick up a new build immediately.
func loadUIAssets() (map[string]uiAsset, string) {
	assets := map[string]uiAsset{}
	all := sha256.New()
	entries, err := fs.ReadDir(uiFiles, "ui")
	if err != nil {
		panic(err)
	}
	for _, e := range entries {
		ext := path.Ext(e.Name())
		if ext != ".css" && ext != ".js" {
			continue
		}
		body := mustReadUI("ui/" + e.Name())
		sum := sha256.Sum256(body)
		all.Write(sum[:])
		assets[e.Name()] = uiAsset{
			body:        body,
			contentType: mime.TypeByExtension(ext),
			etag:        `"` + hex.EncodeToString(sum[:8]) + `"`,
		}
	}
	return assets, hex.EncodeToString(all.Sum(nil)[:6])
}

// serveAsset implements GET {base}/assets/{file}.
func serveAsset(w http.ResponseWriter, r *http.Request) {
	asset, ok := uiAssets[r.PathValue("file")]
	if !ok {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", asset.contentType)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("ETag", asset.etag)
	if r.URL.Query().Get("v") == uiAssetVersion {
		h.Set("Cache-Control", "public, max-age=31536000, immutable")
	} else {
		h.Set("Cache-Control", "no-cache")
	}
	if r.Header.Get("If-None-Match") == asset.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	_, _ = w.Write(asset.body)
}

func assetURL(name string) string {
	return DefaultBasePath + "/assets/" + name + "?v=" + uiAssetVersion
}

// sameOriginRedirect accepts a path, or an absolute URL on this origin (the
// web middleware sends absolute ones), and returns it as a path.
func sameOriginRedirect(origin, raw string) string {
	if p := sanitizeRedirectPath(raw); p != "" {
		return p
	}
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	o, err := url.Parse(origin)
	if err != nil || !strings.EqualFold(u.Scheme, o.Scheme) || !strings.EqualFold(u.Host, o.Host) {
		return ""
	}
	return sanitizeRedirectPath(u.RequestURI() + fragment(u))
}

// allowedInputTypes keeps provider config from producing odd inputs.
var allowedInputTypes = map[string]bool{inputText: true, inputEmail: true, inputPassword: true, inputTel: true, "number": true}

func fieldViews(fields []CredentialField, form string) []fieldView {
	prefix := "ga-" + form + "-"
	register := form == formReg
	out := make([]fieldView, 0, len(fields))
	for _, f := range fields {
		if f.Name == "" {
			continue
		}
		typ := strings.ToLower(f.Type)
		if !allowedInputTypes[typ] {
			typ = inputText
		}
		out = append(out, fieldView{
			ID:           prefix + f.Name,
			Name:         f.Name,
			Label:        cmp.Or(f.Label, strings.ToUpper(f.Name[:1])+f.Name[1:]),
			Type:         typ,
			Placeholder:  f.Placeholder,
			Autocomplete: autocompleteFor(f.Name, typ, register),
			IsPassword:   typ == inputPassword,
		})
	}
	return out
}

// autocompleteFor picks the autocomplete token password managers expect.
func autocompleteFor(name, typ string, register bool) string {
	switch {
	case typ == inputPassword && register:
		return "new-password"
	case typ == inputPassword:
		return "current-password"
	case typ == inputEmail || strings.EqualFold(name, inputEmail):
		return inputEmail
	case strings.EqualFold(name, "name"):
		return "name"
	case strings.EqualFold(name, "username"):
		return "username"
	case typ == inputTel:
		return "tel"
	}
	return "off"
}

// --- Provider icons ---------------------------------------------------------

// Icon keys shared by several provider ids.
const (
	iconMicrosoft = "microsoft"
	iconDirectory = "directory"
)

// providerIcons are small inline SVG marks for well-known providers. They
// are trusted, compiled-in markup.
var providerIcons = map[string]string{
	"google":      `<svg viewBox="0 0 48 48" aria-hidden="true"><path fill="#FFC107" d="M43.611 20.083H42V20H24v8h11.303c-1.649 4.657-6.08 8-11.303 8-6.627 0-12-5.373-12-12s5.373-12 12-12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 12.955 4 4 12.955 4 24s8.955 20 20 20 20-8.955 20-20c0-1.341-.138-2.65-.389-3.917z"/><path fill="#FF3D00" d="M6.306 14.691l6.571 4.819C14.655 15.108 18.961 12 24 12c3.059 0 5.842 1.154 7.961 3.039l5.657-5.657C34.046 6.053 29.268 4 24 4 16.318 4 9.656 8.337 6.306 14.691z"/><path fill="#4CAF50" d="M24 44c5.166 0 9.86-1.977 13.409-5.192l-6.19-5.238A11.91 11.91 0 0 1 24 36c-5.202 0-9.619-3.317-11.283-7.946l-6.522 5.025C9.505 39.556 16.227 44 24 44z"/><path fill="#1976D2" d="M43.611 20.083H42V20H24v8h11.303a12.04 12.04 0 0 1-4.087 5.571l.003-.002 6.19 5.238C36.971 39.205 44 34 44 24c0-1.341-.138-2.65-.389-3.917z"/></svg>`,
	"github":      `<svg viewBox="0 0 16 16" aria-hidden="true"><path fill="currentColor" d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"/></svg>`,
	iconMicrosoft: `<svg viewBox="0 0 21 21" aria-hidden="true"><rect x="1" y="1" width="9" height="9" fill="#f25022"/><rect x="11" y="1" width="9" height="9" fill="#7fba00"/><rect x="1" y="11" width="9" height="9" fill="#00a4ef"/><rect x="11" y="11" width="9" height="9" fill="#ffb900"/></svg>`,
	iconDirectory: `<svg viewBox="0 0 24 24" aria-hidden="true" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 21V5a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v16"/><path d="M16 9h2a2 2 0 0 1 2 2v10"/><path d="M8 7h4M8 11h4M8 15h4M3 21h18"/></svg>`,
}

// providerIconAliases maps provider ids to an icon.
var providerIconAliases = map[string]string{
	"azuread": iconMicrosoft, "azuread-v2": iconMicrosoft, "entra": iconMicrosoft, "microsoft-entra-id": iconMicrosoft,
	"ldap": iconDirectory, "active-directory": iconDirectory, "ad": iconDirectory, "saml": iconDirectory, "sso": iconDirectory,
}

func providerIcon(id, name string) template.HTML {
	key := strings.ToLower(id)
	if alias, ok := providerIconAliases[key]; ok {
		key = alias
	}
	if svg, ok := providerIcons[key]; ok {
		return template.HTML(svg) //nolint:gosec // compiled-in markup, never user input
	}
	letter := "?"
	if r := []rune(strings.TrimSpace(name)); len(r) > 0 {
		letter = strings.ToUpper(string(r[0]))
	}
	return template.HTML(`<span class="ga-monogram" aria-hidden="true">` + template.HTMLEscapeString(letter) + `</span>`) //nolint:gosec // escaped
}
