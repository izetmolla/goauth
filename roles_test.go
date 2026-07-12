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
