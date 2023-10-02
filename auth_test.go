package main

import (
	"net/http"
	"testing"
)

var devOn = struct {
	Enabled  bool   `mapstructure:"enabled"`
	Username string `mapstructure:"username"`
}(struct {
	Enabled  bool
	Username string
}{Enabled: true, Username: ""})

var devOff = struct {
	Enabled  bool   `mapstructure:"enabled"`
	Username string `mapstructure:"username"`
}(struct {
	Enabled  bool
	Username string
}{Enabled: false, Username: ""})

func TestGetBearerToken(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		expected   string
		expectErr  bool
	}{
		{
			name:       "no authorization header",
			authHeader: "",
			expectErr:  true,
		},
		{
			name:       "invalid authorization header",
			authHeader: "Token abc",
			expectErr:  true,
		},
		{
			name:       "valid bearer token",
			authHeader: "Bearer abc123",
			expected:   "abc123",
			expectErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := &http.Request{Header: http.Header{"Authorization": {tt.authHeader}}}
			got, err := trimBearerToken(r)
			if (err != nil) != tt.expectErr {
				t.Errorf("trimBearerToken() error = %v, expectErr %v", err, tt.expectErr)
				return
			}
			if got != tt.expected {
				t.Errorf("trimBearerToken() = %v, want %v", got, tt.expected)
			}
		})
	}
}
