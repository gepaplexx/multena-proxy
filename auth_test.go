package main

import (
	"net/http"
	"testing"

	"github.com/golang-jwt/jwt/v5"
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
			got, err := getBearerToken(r)
			if (err != nil) != tt.expectErr {
				t.Errorf("getBearerToken() error = %v, expectErr %v", err, tt.expectErr)
				return
			}
			if got != tt.expected {
				t.Errorf("getBearerToken() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestIsValidToken(t *testing.T) {
	tests := []struct {
		name     string
		token    *jwt.Token
		config   Config
		expected bool
	}{
		{
			name:     "valid token with dev mode off",
			token:    &jwt.Token{Valid: true},
			config:   Config{Dev: devOff},
			expected: true,
		},
		{
			name:     "invalid token with dev mode on",
			token:    &jwt.Token{Valid: false},
			config:   Config{Dev: devOn},
			expected: true,
		},
		{
			name:     "invalid token with dev mode off",
			token:    &jwt.Token{Valid: false},
			config:   Config{Dev: devOff},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidToken(tt.token, tt.config)
			if got != tt.expected {
				t.Errorf("isValidToken() = %v, want %v", got, tt.expected)
			}
		})
	}
}
