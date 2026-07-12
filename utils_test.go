package goauth

import (
	"testing"
	"time"
)

func TestParseCustomDuration(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		defaultInput string
		want         time.Duration
		wantErr      bool
	}{
		{name: "seconds", input: "30s", want: 30 * time.Second},
		{name: "minutes", input: "15m", want: 15 * time.Minute},
		{name: "hours", input: "1h", want: time.Hour},
		{name: "days", input: "7d", want: 7 * 24 * time.Hour},
		{name: "weeks", input: "4w", want: 4 * 7 * 24 * time.Hour},
		{name: "months", input: "1mo", want: 30 * 24 * time.Hour},
		{name: "years", input: "1y", want: 365 * 24 * time.Hour},
		{name: "empty falls back to default", input: "", defaultInput: "60s", want: 60 * time.Second},
		{name: "missing number", input: "d", wantErr: true},
		{name: "invalid unit", input: "10x", wantErr: true},
		{name: "empty input and default", input: "", defaultInput: "", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCustomDuration(tt.input, tt.defaultInput)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("ParseCustomDuration(%q, %q) = %v, want %v", tt.input, tt.defaultInput, got, tt.want)
			}
		})
	}
}

func TestIsExcludedPath(t *testing.T) {
	tests := []struct {
		name     string
		excluded []string
		path     string
		want     bool
	}{
		{name: "exact match", excluded: []string{"/public"}, path: "/public", want: true},
		{name: "prefix match", excluded: []string{"/public"}, path: "/public/health", want: true},
		{name: "no match", excluded: []string{"/public"}, path: "/private", want: false},
		{name: "empty prefix ignored", excluded: []string{""}, path: "/anything", want: false},
		{name: "no exclusions", excluded: nil, path: "/anything", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := IsExcludedPath(tt.excluded, tt.path); got != tt.want {
				t.Errorf("IsExcludedPath(%v, %q) = %v, want %v", tt.excluded, tt.path, got, tt.want)
			}
		})
	}
}
