package main

import (
	"testing"

	"github.com/prometheus/prometheus/model/labels"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogqlEnforcer(t *testing.T) {
	tests := []struct {
		name          string
		query         string
		tenantLabels  []string
		expectedQuery string
		expectError   bool
	}{
		{
			name:          "Empty query",
			query:         "",
			tenantLabels:  []string{"test-namespace"},
			expectedQuery: "{__name__=~\".+\", kubernetes_namespace_name=\"test-namespace\"}",
		},
		{
			name:          "Valid query",
			query:         "{app=\"my-app\"}",
			tenantLabels:  []string{"test-namespace"},
			expectedQuery: "{app=\"my-app\", kubernetes_namespace_name=\"test-namespace\"}",
		},
		{
			name:         "Invalid query",
			query:        "{app=\"my-app\"|}",
			tenantLabels: []string{"test-namespace"},
			expectError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := logqlEnforcer(tt.query, tt.tenantLabels)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedQuery, result)
			}
		})
	}
}

func TestMatchNamespaceMatchers(t *testing.T) {
	tests := []struct {
		name        string
		qm          []*labels.Matcher
		tl          []string
		expectedQm  []*labels.Matcher
		expectError bool
	}{
		{
			name: "Valid matchers",
			qm: []*labels.Matcher{
				{Type: labels.MatchEqual, Name: "app", Value: "my-app"},
			},
			tl: []string{"test-namespace"},
			expectedQm: []*labels.Matcher{
				{Type: labels.MatchEqual, Name: "app", Value: "my-app"},
				{Type: labels.MatchEqual, Name: "kubernetes_namespace_name", Value: "test-namespace"},
			},
		},
		{
			name: "Unauthorized namespace",
			qm: []*labels.Matcher{
				{Type: labels.MatchEqual, Name: "kubernetes_namespace_name", Value: "unauthorized-namespace"},
			},
			tl:          []string{"test-namespace"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := matchNamespaceMatchers(tt.qm, tt.tl)

			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedQm, result)
			}
		})
	}
}

func TestAllStringsInList(t *testing.T) {
	tests := []struct {
		name           string
		list1          []string
		list2          []string
		expectedResult bool
	}{
		{
			name:           "All strings in list",
			list1:          []string{"a", "b"},
			list2:          []string{"a", "b", "c"},
			expectedResult: true,
		},
		{
			name:           "Not all strings in list",
			list1:          []string{"a", "b", "d"},
			list2:          []string{"a", "b", "c"},
			expectedResult: false,
		},
		{
			name:           "Empty list1",
			list1:          []string{},
			list2:          []string{"a", "b", "c"},
			expectedResult: true,
		},
		{
			name:           "Empty list2",
			list1:          []string{"a", "b"},
			list2:          []string{},
			expectedResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _ := allStringsInList(tt.list1, tt.list2)
			assert.Equal(t, tt.expectedResult, result)
		})
	}
}
