package utils

import "strings"

// Contains returns true if the string slice contains the string
func Contains[T comparable](s []T, e T) bool {
	for _, v := range s {

		if v == e {
			return true
		}
	}
	return false
}

// ContainsIgnoreCase returns true if the string slice contains the string ignoring case sensitivity
func ContainsIgnoreCase(s []string, e string) bool {
	for _, v := range s {

		if strings.ToLower(v) == strings.ToLower(e) {
			return true
		}
	}
	return false
}
