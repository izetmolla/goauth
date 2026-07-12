package goauth

import (
	"reflect"
	"testing"
)

func TestFormatRoles(t *testing.T) {
	tests := []struct {
		name  string
		roles JSONBArray
		want  []string
	}{
		{
			name:  "nil",
			roles: nil,
			want:  []string{},
		},
		{
			name:  "empty",
			roles: JSONBArray{},
			want:  []string{},
		},
		{
			name:  "multiple grants",
			roles: JSONBArray{"admin:rw", "hr:r"},
			want:  []string{"admin:rw", "hr:r"},
		},
		{
			name:  "single grant from any slice",
			roles: JSONBArray([]any{"admin:rw"}),
			want:  []string{"admin:rw"},
		},
		{
			name:  "trims whitespace and drops blank entries",
			roles: JSONBArray{"  admin:rw  ", "", "   ", "hr:r"},
			want:  []string{"admin:rw", "hr:r"},
		},
		{
			name:  "skips non-string elements",
			roles: JSONBArray{"admin:rw", 42, nil, "hr:r"},
			want:  []string{"admin:rw", "hr:r"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := FormatRoles(tt.roles)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FormatRoles(%v) = %v, want %v", tt.roles, got, tt.want)
			}
		})
	}
}

func TestRolesFromAny(t *testing.T) {
	tests := []struct {
		name    string
		raw     any
		want    []string
		wantErr bool
	}{
		{
			name: "string slice",
			raw:  []string{"admin:rw", "  hr:r  ", ""},
			want: []string{"admin:rw", "hr:r"},
		},
		{
			name: "jsonb array",
			raw:  JSONBArray{"admin:rw"},
			want: []string{"admin:rw"},
		},
		{
			// JWT claims decode JSON arrays as []any; non-string entries
			// must be skipped, not turn into an error.
			name: "any slice with non-string entries",
			raw:  []any{"admin:rw", nil, 42.0, "hr:r"},
			want: []string{"admin:rw", "hr:r"},
		},
		{
			name: "single grant string",
			raw:  "admin:rw",
			want: []string{"admin:rw"},
		},
		{
			// A JSON-encoded array must be parsed into individual grants,
			// not treated as one giant grant string.
			name: "json-encoded array string",
			raw:  `["admin:rw","hr:r"]`,
			want: []string{"admin:rw", "hr:r"},
		},
		{
			name:    "malformed json array string",
			raw:     `["admin:rw"`,
			wantErr: true,
		},
		{
			name:    "empty string",
			raw:     "   ",
			wantErr: true,
		},
		{
			name:    "unsupported type",
			raw:     42,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rolesFromAny(tt.raw)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("rolesFromAny(%v) expected error, got %v", tt.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("rolesFromAny(%v) unexpected error: %v", tt.raw, err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("rolesFromAny(%v) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}

func TestGetRole(t *testing.T) {
	a := &Authorization{}

	tests := []struct {
		name          string
		endpointRoles []string
		userRoles     []string
		wantHas       bool
		wantRead      bool
		wantWrite     bool
	}{
		{
			name:          "read-write grant",
			endpointRoles: []string{"admin"},
			userRoles:     []string{"admin:rw"},
			wantHas:       true, wantRead: true, wantWrite: true,
		},
		{
			name:          "read-only grant",
			endpointRoles: []string{"hr"},
			userRoles:     []string{"hr:r"},
			wantHas:       true, wantRead: true, wantWrite: false,
		},
		{
			name:          "write-only grant",
			endpointRoles: []string{"hr"},
			userRoles:     []string{"hr:w"},
			wantHas:       true, wantRead: false, wantWrite: true,
		},
		{
			name:          "case-insensitive name match",
			endpointRoles: []string{"Admin"},
			userRoles:     []string{"ADMIN:rw"},
			wantHas:       true, wantRead: true, wantWrite: true,
		},
		{
			name:          "endpoint role with perms suffix compares name only",
			endpointRoles: []string{"admin:rw"},
			userRoles:     []string{"admin:r"},
			wantHas:       true, wantRead: true, wantWrite: false,
		},
		{
			name:          "no matching role",
			endpointRoles: []string{"finance"},
			userRoles:     []string{"admin:rw"},
			wantHas:       false, wantRead: false, wantWrite: false,
		},
		{
			name:          "empty user roles",
			endpointRoles: []string{"admin"},
			userRoles:     nil,
			wantHas:       false, wantRead: false, wantWrite: false,
		},
		{
			name:          "grant without perms matches but grants nothing",
			endpointRoles: []string{"admin"},
			userRoles:     []string{"admin"},
			wantHas:       true, wantRead: false, wantWrite: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			has, read, write := a.GetRole(tt.endpointRoles, tt.userRoles)
			if has != tt.wantHas || read != tt.wantRead || write != tt.wantWrite {
				t.Errorf("GetRole(%v, %v) = (%v, %v, %v), want (%v, %v, %v)",
					tt.endpointRoles, tt.userRoles, has, read, write,
					tt.wantHas, tt.wantRead, tt.wantWrite)
			}
		})
	}
}
