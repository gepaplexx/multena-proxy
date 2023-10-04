package main

import "strings"

func ContainsIgnoreCase(s []string, e string) bool {
	for _, v := range s {
		if strings.EqualFold(v, e) {
			return true
		}
	}
	return false
}

func MapKeysToArray[K comparable, V any](tenantLabel map[K]V) []K {
	tenantLabelKeys := make([]K, 0, len(tenantLabel))
	for key := range tenantLabel {
		tenantLabelKeys = append(tenantLabelKeys, key)
	}
	return tenantLabelKeys
}
