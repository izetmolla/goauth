package goauth

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	htmltemplate "html/template"
	"io/fs"
	"strings"
	texttemplate "text/template"
	"time"
)

// emailTemplates holds one parsed template set per verification kind. Each
// file defines "subject", "preheader", "text" and "html"; layout.html
// defines the HTML shell ("layout") and the "button" and "code" blocks.
// Subject and text are rendered with text/template (no HTML escaping, so
// links stay intact); the HTML body with html/template.
type emailTemplates struct {
	html map[VerificationKind]*htmltemplate.Template
	text map[VerificationKind]*texttemplate.Template
}

var emailKinds = []VerificationKind{KindPasswordReset, KindEmailConfirmation, KindOTPSignIn}

// readEmailFile prefers the override FS and falls back to the built-in file.
func readEmailFile(override fs.FS, name string) ([]byte, error) {
	if override != nil {
		b, err := fs.ReadFile(override, name)
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	}
	return uiFiles.ReadFile("ui/email/" + name)
}

func loadEmailTemplates(override fs.FS) (*emailTemplates, error) {
	layout, err := readEmailFile(override, "layout.html")
	if err != nil {
		return nil, err
	}
	t := &emailTemplates{
		html: map[VerificationKind]*htmltemplate.Template{},
		text: map[VerificationKind]*texttemplate.Template{},
	}
	for _, kind := range emailKinds {
		name := string(kind) + ".html"
		body, err := readEmailFile(override, name)
		if err != nil {
			return nil, err
		}
		h, err := htmltemplate.New(name).Parse(string(layout))
		if err == nil {
			_, err = h.Parse(string(body))
		}
		if err != nil {
			return nil, fmt.Errorf("email template %s: %w", name, err)
		}
		x, err := texttemplate.New(name).Parse(string(layout))
		if err == nil {
			_, err = x.Parse(string(body))
		}
		if err != nil {
			return nil, fmt.Errorf("email template %s: %w", name, err)
		}
		for _, block := range []string{"subject", "text", "html"} {
			if h.Lookup(block) == nil {
				return nil, fmt.Errorf("email template %s must define %q", name, block)
			}
		}
		t.html[kind], t.text[kind] = h, x
	}
	return t, nil
}

// EmailData is what email templates receive.
type EmailData struct {
	Kind        VerificationKind
	AppName     string
	LogoURL     string
	Initial     string
	Accent      htmltemplate.CSS
	Email       string
	Code        string
	Link        string
	ButtonLabel string
	ExpiresIn   string
}

// renderEmail fills msg.Subject, msg.Text and msg.HTML.
func (a *Authorization) renderEmail(msg *VerificationMessage) error {
	app := cmp.Or(a.ui.AppName, "your account")
	initial := "✓"
	if a.ui.AppName != "" {
		initial = strings.ToUpper(string([]rune(a.ui.AppName)[0]))
	}
	data := EmailData{
		Kind:      msg.Kind,
		AppName:   app,
		LogoURL:   a.ui.LogoURL,
		Initial:   initial,
		Accent:    htmltemplate.CSS(cmp.Or(a.ui.AccentColor, "#4f46e5")), // validated in New
		Email:     msg.To,
		Code:      msg.Code,
		Link:      msg.Link,
		ExpiresIn: humanDuration(time.Until(msg.ExpiresAt)),
	}
	switch msg.Kind {
	case KindPasswordReset:
		data.ButtonLabel = "Choose a new password"
	case KindEmailConfirmation:
		data.ButtonLabel = "Confirm email"
	default:
		data.ButtonLabel = "Sign in to " + app
	}

	var subject, text, html bytes.Buffer
	x := a.verify.emails.text[msg.Kind]
	if err := x.ExecuteTemplate(&subject, "subject", data); err != nil {
		return err
	}
	if err := x.ExecuteTemplate(&text, "text", data); err != nil {
		return err
	}
	if err := a.verify.emails.html[msg.Kind].ExecuteTemplate(&html, "layout", data); err != nil {
		return err
	}
	msg.Subject = strings.Join(strings.Fields(subject.String()), " ")
	msg.Text = strings.TrimSpace(text.String()) + "\n"
	msg.HTML = html.String()
	return nil
}

// humanDuration renders a TTL the way people say it: "10 minutes", "1 hour",
// "24 hours", "3 days".
func humanDuration(d time.Duration) string {
	d = d.Round(time.Minute)
	plural := func(n int, unit string) string {
		if n == 1 {
			return "1 " + unit
		}
		return fmt.Sprintf("%d %ss", n, unit)
	}
	switch {
	case d >= 72*time.Hour && d%(24*time.Hour) == 0:
		return plural(int(d/(24*time.Hour)), "day")
	case d >= time.Hour && d%time.Hour == 0:
		return plural(int(d/time.Hour), "hour")
	case d >= time.Minute:
		return plural(int(d/time.Minute), "minute")
	default:
		return "less than a minute"
	}
}
