package main

import (
	"net/http"
	"strings"
)

func HeaderRewriter(request *http.Request, labels []string) {
	request.Header.Set("X-Scope-OrgID", strings.Join(labels, "|"))
}
