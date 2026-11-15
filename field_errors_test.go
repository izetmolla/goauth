package goauth

import (
	"net/http"
	"strings"
	"testing"
)

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
	body := do(t, h, http.MethodGet, DefaultBasePath+"/otp?step=code&email=a%40b.co&error=INVALID_CODE&field=code", nil, nil).Body.String()
	if !strings.Contains(body, `id="ga-code-error"`) || alertShown(body) {
		t.Error("invalid code not shown under the code input")
	}
	body = do(t, h, http.MethodGet, DefaultBasePath+"/forgot?error=INVALID_EMAIL&field=email", nil, nil).Body.String()
	if !strings.Contains(body, `id="ga-email-error"`) || alertShown(body) {
		t.Error("invalid email not shown under the email input")
	}
	// A password error on the reset step has no server-rendered slot: alert.
	body = do(t, h, http.MethodGet, DefaultBasePath+"/forgot?step=code&email=a%40b.co&error=WEAK_PASSWORD&field=password", nil, nil).Body.String()
	if !alertShown(body) {
		t.Error("unplaced password error should use the alert")
	}
}
