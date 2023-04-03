package main

import (
	"testing"
)

type urlRewriteTest struct {
	tenantLabel string
	labels      []string
	url         string
	expected    string
	shouldFail  bool
}

// url constist of example promql query
var urlRewriteTests = []urlRewriteTest{
	{"namespace", []string{"hogorama", "minio"}, "http://localhost:8080/api/v1/namespaces?labelSelector=gp-dev", "http://localhost:8080/api/v1/namespaces?namespace=hogorama&namespace=minio&labelSelector=gp-dev", false},
	{"namespace", []string{"hogorama", "minio"}, "http://localhost:8080/api/v1/namespaces?labelSelector=gp-dev", "http://localhost:8080/api/v1/namespaces?namespace=jsdhfsjkdhfkshjf", true},
}

func TestURLRewrite(t *testing.T) {
	for _, test := range urlRewriteTests {
		if output := UrlRewriter(test.url, test.labels, test.tenantLabel); (output != test.expected) != (test.shouldFail) {
			t.Errorf("Output %q not equal to expected %q", output, test.expected)
		}
	}
}
