package main

import "strings"

// ContainsIgnoreCase checks if a given string 'e' exists in the provided string slice 's'.
// It ignores the case while comparing the strings. Returns true if 'e' is present in 's',
// otherwise returns false.
func ContainsIgnoreCase(s []string, e string) bool {
	for _, v := range s {
		if strings.EqualFold(v, e) {
			return true
		}
	}
	return false
}

// MapKeysToArray extracts the keys from the given map and returns them as a slice.
// The map keys and values can be of any types.
// It uses Go generics to support generic map keys and values.
func MapKeysToArray[K comparable, V any](tenantLabel map[K]V) []K {
	tenantLabelKeys := make([]K, 0, len(tenantLabel))
	for key := range tenantLabel {
		tenantLabelKeys = append(tenantLabelKeys, key)
	}
	return tenantLabelKeys
}

func teardown() {
	InitConfig()
}
