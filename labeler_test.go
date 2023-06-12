package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Setting up the Config
func setupTestLabeler() {
	Cfg.Users["user1"] = []string{"tenant1", "tenant2"}
	Cfg.Users["user2"] = []string{"tenant3", "tenant4"}
	Cfg.Groups["group1"] = []string{"tenant1", "tenant3"}
	Cfg.Groups["group2"] = []string{"tenant2", "tenant4"}
}

// Resetting the Config

func TestGetLabelsCM(t *testing.T) {
	setupTestLabeler()
	defer teardown()

	cases := []struct {
		name     string
		username string
		groups   []string
		expected map[string]bool
	}{
		{
			name:     "User with groups",
			username: "user1",
			groups:   []string{"group1", "group2"},
			expected: map[string]bool{
				"tenant1": true,
				"tenant2": true,
				"tenant3": true,
				"tenant4": true,
			},
		},
		{
			name:     "User without groups",
			username: "user2",
			groups:   []string{},
			expected: map[string]bool{
				"tenant3": true,
				"tenant4": true,
			},
		},
		{
			name:     "Non-existent user",
			username: "user3",
			groups:   []string{"group1"},
			expected: map[string]bool{
				"tenant1": true,
				"tenant3": true,
			},
		},
		{
			name:     "Non-existent group",
			username: "user1",
			groups:   []string{"group3"},
			expected: map[string]bool{
				"tenant1": true,
				"tenant2": true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			labels := GetLabelsCM(tc.username, tc.groups)
			assert.Equal(t, tc.expected, labels)
		})
	}
}
