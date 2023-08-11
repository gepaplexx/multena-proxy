package main

import (
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/assert"
)

func TestLogqlEnforcer(t *testing.T) {
	tests := []struct {
		name           string
		query          string
		tenantLabels   map[string]bool
		expectedResult string
		expectErr      bool
	}{
		{
			name:           "Valid query and tenant labels",
			query:          "{kubernetes_namespace_name=\"test\"}",
			tenantLabels:   map[string]bool{"test": true},
			expectedResult: "{kubernetes_namespace_name=\"test\"}",
			expectErr:      false,
		},
		{
			name:           "Empty query and valid tenant labels",
			query:          "",
			tenantLabels:   map[string]bool{"test": true},
			expectedResult: "{__name__=~\".+\", kubernetes_namespace_name=\"test\"}",
			expectErr:      false,
		},
		{
			name:         "Valid query and invalid tenant labels",
			query:        "{kubernetes_namespace_name=\"test\"}",
			tenantLabels: map[string]bool{"invalid": true},
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := LogQLEnforcer{}.EnforceQL(tt.query, tt.tenantLabels)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}

func TestMatchNamespaceMatchers(t *testing.T) {
	tests := []struct {
		name         string
		matchers     []*labels.Matcher
		tenantLabels map[string]bool
		expectErr    bool
	}{
		{
			name: "Valid matchers and tenant labels",
			matchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "test",
				},
			},
			tenantLabels: map[string]bool{"test": true},
			expectErr:    false,
		},
		{
			name: "Invalid matchers and valid tenant labels",
			matchers: []*labels.Matcher{
				{
					Type:  labels.MatchEqual,
					Name:  "kubernetes_namespace_name",
					Value: "invalid",
				},
			},
			tenantLabels: map[string]bool{"test": true},
			expectErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := matchNamespaceMatchers(tt.matchers, tt.tenantLabels)
			if tt.expectErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
