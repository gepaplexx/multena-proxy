package main

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

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

func TestTrimBearerToken(t *testing.T) {
	assert := assert.New(t)

	tests := []struct {
		name          string
		headerValue   string
		expectedToken string
		expectError   bool
	}{
		{
			name:          "Valid token",
			headerValue:   "Bearer example_token",
			expectedToken: "example_token",
			expectError:   false,
		},
		{
			name:          "No Authorization header",
			headerValue:   "",
			expectedToken: "",
			expectError:   true,
		},
		{
			name:          "No Authorization header",
			headerValue:   "totally a jwt",
			expectedToken: "",
			expectError:   true,
		},
		{
			name:          "Token with space",
			headerValue:   "Bearer token_with_space ",
			expectedToken: "token_with_space",
			expectError:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "http://example.com", nil)
			req.Header.Set("Authorization", tt.headerValue)

			token, err := trimBearerToken(req)

			assert.Equal(tt.expectedToken, token)

			if tt.expectError {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}
		})
	}
}
