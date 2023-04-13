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
