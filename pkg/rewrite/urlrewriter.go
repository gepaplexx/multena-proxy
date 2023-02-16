package rewrite

import (
	"fmt"
	"strings"
)

func UrlRewriter(URL string, labels []string, tenantLabel string) string {
	// write tests for this function and make it more robust
	quIn := strings.Index(URL, "?")
	if quIn == -1 {
		URL += "?"
		quIn = len(URL)
	} else {
		quIn += 1
	}

	labelsEnforcer := ""
	for _, label := range labels {
		labelsEnforcer += fmt.Sprintf("%s=%s&", tenantLabel, label)
	}
	if labelsEnforcer != "" {
		labelsEnforcer = labelsEnforcer[:len(labelsEnforcer)-1]
	}
	url := URL[:quIn] + labelsEnforcer + URL[quIn:]
	return url
}
