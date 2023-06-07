package main

import (
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestContainsIgnoreCase(t *testing.T) {
	slice := []string{"apple", "banana", "orange"}

	// Test case: Element exists in the slice (case-insensitive match)
	assert.True(t, ContainsIgnoreCase(slice, "Banana"))

	// Test case: Element exists in the slice (exact case match)
	assert.True(t, ContainsIgnoreCase(slice, "banana"))

	// Test case: Element does not exist in the slice
	assert.False(t, ContainsIgnoreCase(slice, "grape"))
}

func TestMapKeysToArray(t *testing.T) {
	// Test case: Map with string keys
	stringMap := map[string]int{"a": 1, "b": 2, "c": 3}
	stringKeys := MapKeysToArray(stringMap)

	// Sort the keys
	sort.Strings(stringKeys)

	expectedStringKeys := []string{"a", "b", "c"}
	assert.Equal(t, expectedStringKeys, stringKeys)

	// Test case: Map with int keys
	intMap := map[int]string{1: "a", 2: "b", 3: "c"}
	intKeys := MapKeysToArray(intMap)

	// Sort the keys
	sort.Ints(intKeys)

	expectedIntKeys := []int{1, 2, 3}
	assert.Equal(t, expectedIntKeys, intKeys)
}
