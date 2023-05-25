package main

import "strings"

// ContainsIgnoreCase returns true if the string slice contains the string ignoring case sensitivity
func ContainsIgnoreCase(s []string, e string) bool {
	for _, v := range s {
		if strings.EqualFold(v, e) {
			return true
		}
	}
	return false
}

func MapKeysToArray(tl map[string]bool) []string {
	tlk := make([]string, 0, len(tl))
	for k := range tl {
		tlk = append(tlk, k)
	}
	return tlk
}
