package goauth

import (
	"net/http"
	"strings"
	"testing"
)

// formHTML returns the form starting at marker, up to its closing tag.
func formHTML(t *testing.T, body, marker string) string {
	t.Helper()
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("form %s not found", marker)
	}
	j := strings.Index(body[i:], "</form>")
	if j < 0 {
		t.Fatalf("form %s not closed", marker)
	}
	return body[i : i+j]
}

// alertShown reports whether the top error alert is visible.
func alertShown(body string) bool {
	i := strings.Index(body, `id="ga-error"`)
	tag := body[i : i+strings.Index(body[i:], ">")]
	return !strings.Contains(tag, "hidden")
}

func TestNoJSFieldErrorGoesUnderTheInput(t *testing.T) {
	h := uiAuth(t, Config{}).Handler()
	body := do(t, h, http.MethodGet, DefaultBasePath+"/signin?error=CREDENTIALS_SIGNIN&field=password", nil, nil).Body.String()
	if !strings.Contains(body, `id="ga-signin-password-error"`) ||
		!strings.Contains(body, `aria-describedby="ga-signin-password-error"`) ||
		!strings.Contains(body, `<span>Those credentials didn&#39;t work.`) {
		t.Fatal("password error not rendered under the password input")
	}
	if alertShown(body) {
		t.Error("top alert shown although the error is under the input")
	}
	if strings.Contains(body, `id="ga-signin-email-error"`) {
		t.Error("email input marked too")
	}
}

func TestNoJSErrorWithoutFieldUsesAlert(t *testing.T) {
	h := uiAuth(t, Config{}).Handler()
	for _, q := range []string{"?error=CSRF", "?error=CREDENTIALS_SIGNIN&field=nonexistent", `?error=CSRF&field="><script>`} {
		body := do(t, h, http.MethodGet, DefaultBasePath+"/signin"+q, nil, nil).Body.String()
		if !alertShown(body) || strings.Contains(body, `class="ga-field-error"`) {
			t.Errorf("%s: want the top alert and no field error", q)
		}
		if strings.Contains(body, "<script>\"") || strings.Contains(body, `"><script>`) {
			t.Errorf("%s: field name reflected into the page", q)
		}
	}
}

func TestNoJSCodeAndEmailErrorsOnVerificationPages(t *testing.T) {
	h := mustNew(t, allFeatures(UIOptions{EnableAllUI: true})).Handler()
	body := do(t, h, http.MethodGet, DefaultBasePath+"/otp?step=code&vid=7d3c5c8e-2a0e-4c55-9f43-5d9a8a2b7f10&error=INVALID_CODE&field=code", nil, nil).Body.String()
	if !strings.Contains(body, `id="ga-code-error"`) || alertShown(body) {
		t.Error("invalid code not shown under the code input")
	}
	body = do(t, h, http.MethodGet, DefaultBasePath+"/forgot?error=INVALID_EMAIL&field=email", nil, nil).Body.String()
	if !strings.Contains(body, `id="ga-email-error"`) || alertShown(body) {
		t.Error("invalid email not shown under the email input")
	}
	// A password error on the reset step has no server-rendered slot: alert.
	body = do(t, h, http.MethodGet, DefaultBasePath+"/forgot?step=reset&vid=7d3c5c8e-2a0e-4c55-9f43-5d9a8a2b7f10&token=t&error=WEAK_PASSWORD&field=password", nil, nil).Body.String()
	if !alertShown(body) {
		t.Error("unplaced password error should use the alert")
	}
}

func TestPagesNeverPutEmailInURLs(t *testing.T) {
	h := mustNew(t, allFeatures(UIOptions{EnableAllUI: true})).Handler()
	// An email in the query string is ignored, not echoed into the page.
	for _, p := range []string{"/forgot", "/otp", "/verify-email"} {
		body := do(t, h, http.MethodGet, DefaultBasePath+p+"?email=secret%40example.com", nil, nil).Body.String()
		if strings.Contains(body, "secret@example.com") || strings.Contains(body, "secret%40example.com") {
			t.Errorf("%s echoes an email from the URL", p)
		}
	}
	// Code steps need a verification id, not an email.
	body := do(t, h, http.MethodGet, DefaultBasePath+"/forgot?step=code&email=a%40b.co", nil, nil).Body.String()
	if !strings.Contains(body, `data-step="request"`) {
		t.Error("code step shown without a vid")
	}
	vid := "7d3c5c8e-2a0e-4c55-9f43-5d9a8a2b7f10"
	body = do(t, h, http.MethodGet, DefaultBasePath+"/forgot?step=code&vid="+vid, nil, nil).Body.String()
	if !strings.Contains(body, `data-step="code"`) || !strings.Contains(body, `name="vid" value="`+vid+`"`) {
		t.Error("code step with vid not rendered with the vid")
	}
	// The code step asks for the code only; passwords come after.
	codeForm := formHTML(t, body, `data-for="code" novalidate`)
	if strings.Contains(codeForm, `name="password"`) {
		t.Error("code step still asks for the new password")
	}
	resetForm := formHTML(t, body, `data-for="reset" novalidate`)
	if !strings.Contains(resetForm, `name="password"`) || !strings.Contains(resetForm, `name="password_confirm"`) {
		t.Error("reset step must ask for the password twice")
	}
	// A bogus vid is dropped.
	body = do(t, h, http.MethodGet, DefaultBasePath+"/otp?step=code&vid=not-a-uuid", nil, nil).Body.String()
	if !strings.Contains(body, `data-step="request"`) {
		t.Error("invalid vid accepted")
	}
}
