package goauth

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
)

// renderCallbackPage renders a small HTML page that persists the token
// response in localStorage under "authorization-storage" (matching the
// frontend zustand persist format) and either notifies the opener (popup
// flow) or redirects to the saved redirect URL (redirect flow).
func (a *Authorization) renderCallbackPage(w http.ResponseWriter, data any) {
	// json.Marshal escapes <, > and &, so the payload cannot close the
	// surrounding <script> element.
	jsonData, err := json.Marshal(data)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "Failed to encode token response")
		return
	}
	var buf bytes.Buffer
	if err := callbackPageTemplate.Execute(&buf, map[string]any{
		"title":         "Signing in…",
		"globalOptions": template.HTML(`<script id="__GLOBAL_DATA__" type="application/json">` + string(jsonData) + `</script>`), //nolint:gosec // json.Marshal escapes <, > and &
		"sessionJS":     sessionJS,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}

// renderCallbackError renders the callback page in its error state.
func (a *Authorization) renderCallbackError(w http.ResponseWriter, message string) {
	a.renderCallbackPage(w, Map{"message": message, "code": codeError, "signin_url": a.signInPagePath()})
}

var callbackPageTemplate = template.Must(template.New("callback").Parse(tokenCallbackHTML))

const tokenCallbackHTML = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>{{.title}}</title>
<style>
  body{display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;font-family:system-ui,sans-serif;color-scheme:light dark}
  .panel{display:flex;flex-direction:column;align-items:center;gap:12px;max-width:28rem;padding:0 16px;text-align:center}
  .status{display:flex;align-items:center;color:#52525b}
  .status.is-hidden{display:none}
  .spinner{width:24px;height:24px;border:3px solid #8883;border-top-color:#666;border-radius:50%;animation:spin .6s linear infinite;margin-right:12px}
  @keyframes spin{to{transform:rotate(360deg)}}
  #message{margin:0;padding:12px 16px;border-radius:10px;font-size:15px;line-height:1.5;font-weight:500}
  #message.is-error{color:#991b1b;background:#fef2f2;border:1px solid #fecaca}
  #message.is-success{color:#166534;background:#f0fdf4;border:1px solid #bbf7d0}
  .back-btn{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:0 16px;border:1px solid #d4d4d8;border-radius:8px;background:#fff;color:#18181b;font-family:inherit;font-size:14px;font-weight:500;text-decoration:none;cursor:pointer}
  .back-btn:hover{background:#f4f4f5}
  .close-btn{display:inline-flex;align-items:center;justify-content:center;min-height:40px;padding:0 16px;border:1px solid #d4d4d8;border-radius:8px;background:#fff;color:#18181b;font-family:inherit;font-size:14px;font-weight:500;cursor:pointer}
  .close-btn:hover{background:#f4f4f5}
  @media (prefers-color-scheme:dark){
    .status{color:#a1a1aa}
    #message.is-error{color:#fecaca;background:#450a0a;border-color:#7f1d1d}
    #message.is-success{color:#bbf7d0;background:#052e16;border-color:#166534}
    .back-btn{border-color:#3f3f46;background:#18181b;color:#fafafa}
    .back-btn:hover{background:#27272a}
    .close-btn{border-color:#3f3f46;background:#18181b;color:#fafafa}
    .close-btn:hover{background:#27272a}
  }
</style>
{{.globalOptions}}
</head>
<body>
<div class="panel">
  <div id="status" class="status"><div class="spinner"></div>Completing sign-in…</div>
  <p id="message"></p>
  <button id="back-to-sign-in" type="button" class="back-btn" hidden>Back to sign in</button>
  <button id="close-tab" type="button" class="close-btn" hidden>Close this tab</button>
</div>

<script>
function getGlobalOptionsJson() {
    const el = document.getElementById('__GLOBAL_DATA__');
    if (!el) return {};
    try {
        return JSON.parse(el.textContent || '{}')
    } catch {
        return {}
    }
}
const globalOptions = getGlobalOptionsJson();
const statusEl = document.getElementById('status');
const messageEl = document.getElementById('message');
const backToSignInEl = document.getElementById('back-to-sign-in');
const closeTabEl = document.getElementById('close-tab');

function closeCurrentTab() {
	if (window.opener && !window.opener.closed) {
		try {
			window.close();
		} catch (_) {}
	}
	if (!window.closed) {
		window.close();
	}
}

if (closeTabEl) {
	closeTabEl.addEventListener('click', closeCurrentTab);
}

function redirectTo(url) {
	window.location.replace(url);
}

if (backToSignInEl) {
	backToSignInEl.addEventListener('click', function () {
		redirectTo(globalOptions.signin_url || '/sign-in');
	});
}

function showError(message) {
	if (statusEl) statusEl.classList.add('is-hidden');
	if (messageEl) {
		messageEl.textContent = message || 'Sign-in failed';
		messageEl.className = 'is-error';
		messageEl.hidden = false;
	}
	if (backToSignInEl) backToSignInEl.hidden = Boolean(globalOptions?.user);
}

function showSuccess(message, options) {
	const opts = options || {};
	if (statusEl) statusEl.classList.add('is-hidden');
	if (messageEl) {
		messageEl.textContent = message || 'Signed in successfully. Redirecting…';
		messageEl.className = 'is-success';
		messageEl.hidden = false;
	}
	if (backToSignInEl) backToSignInEl.hidden = true;
	if (closeTabEl) closeTabEl.hidden = !opts.showCloseTab;
}

{{.sessionJS}}

function persistSignIn(data) {
	return GoAuthSession.persist(data);
}

function finishSignIn(snapshot, message) {
	// redirect_url is set by the server (already validated as same-origin)
	// for credentials sign-ins; OAuth sign-ins use the stored redirectUrl.
	const redirectTarget = globalOptions.redirect_url || snapshot.redirectUrl || '/';
	const successMessage = message || 'Signed in successfully. Redirecting…';

	showSuccess(successMessage);

	window.setTimeout(function () {
		if (window.opener && !window.opener.closed) {
			try {
				window.opener.postMessage(
					{ type: 'authorization-sign-in', session_id: snapshot.current_session },
					window.location.origin
				);
			} catch (_) {}
			window.close();
			return;
		}
		redirectTo(redirectTarget);
	}, 900);
}

function finishConnect(message, resourceId) {
	const successMessage = message || 'Microsoft account connected successfully.';

	showSuccess(successMessage, { showCloseTab: true });

	if (window.opener && !window.opener.closed) {
		try {
			window.opener.postMessage(
				{ type: 'microsoft-connect-completed', resource_id: resourceId || '' },
				window.location.origin
			);
		} catch (_) {}
	}
}

if (globalOptions?.code === 'ERROR') {
	showError(globalOptions?.message);
} else if (globalOptions?.type === "sign_in") {
	if (globalOptions?.user && globalOptions?.tokens) {
		const snapshot = persistSignIn({
			session_id: globalOptions.session_id,
			user: globalOptions.user,
			tokens: globalOptions.tokens,
			trusted: globalOptions.trusted
		});
		finishSignIn(snapshot, globalOptions?.message);
	} else {
		showError('Failed to sign in, no user or tokens found');
	}
} else if (globalOptions?.type === 'connect' && globalOptions?.code === 'SUCCESS') {
	finishConnect(globalOptions?.message, globalOptions?.resource_id);
} else if (globalOptions?.type === "get_session") {
	showError('Not implemented');
}


</script>
</body>
</html>`
