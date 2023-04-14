package main

import (
	"errors"
	"fmt"
	"os"
	"testing"
)

type enforceTest struct {
	query      string
	namespaces []string
	expected   string
	error      error
}

var enforceTests = []enforceTest{
	{`sum(rate({level="error"} [$__interval]))`, []string{"tenant1", "openshift-logging"}, `sum(rate({level="error", kubernetes_namespace_name=~"tenant1|openshift-logging"} [$__interval]))`, nil},
	{`sum(rate({level="error", kubernetes_host="worker21"} [$__interval]))`, []string{"tenant1", "openshift-logging"}, `sum(rate({level="error", kubernetes_host="worker21", kubernetes_namespace_name=~"tenant1|openshift-logging"} [$__interval]))`, nil},
	{`sum(rate({level="error", kubernetes_host="worker21", kubernetes_namespace_name="gepaplexx-cicd-tools"} [$__interval]))`, []string{"tenant1", "gepaplexx-cicd-tools"}, `sum(rate({level="error", kubernetes_host="worker21", kubernetes_namespace_name="gepaplexx-cicd-tools"} [$__interval]))`, nil},
	{`sum(rate({level="error", kubernetes_host="worker21", kubernetes_namespace_name="gepaplexx-cicd-tools"} [$__interval]))`, []string{"tenant1", "tenant2"}, ``, errors.New("query contains disallowed namespaces")},
	{`sum(rate({level="error", kubernetes_host="worker21", kubernetes_namespace_name=~"gepaplexx-cicd-tools|tenant1"} [$__interval]))`, []string{"tenant1", "gepaplexx-cicd-tools", "tenant3", "tenant_blubb"}, `sum(rate({level="error", kubernetes_host="worker21", kubernetes_namespace_name=~"gepaplexx-cicd-tools|tenant1"} [$__interval]))`, nil},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} |= `message` | json | line_format `{{.message}}` |= `message` | json | unpack | line_format `{{.message}}` [$__interval]))", []string{"multena"}, "sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} |= `message` | json | line_format `{{.message}}` |= `message` | json | unpack | line_format `{{.message}}` [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} |= `message` | json | line_format `{{.message}}` |= `message` | json | unpack | line_format `{{.message}}` [$__interval]))", []string{"multena", "tenant2"}, "sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} |= `message` | json | line_format `{{.message}}` |= `message` | json | unpack | line_format `{{.message}}` [$__interval]))", nil},
	{"sum by(level) (rate({level=~\"error|default\"} |= `message` | json | line_format `{{.message}}` |= `message` | json | unpack | line_format `{{.message}}` [$__interval]))", []string{"multena", "tenant2", "tenant3"}, "sum by(level) (rate({level=~\"error|default\", kubernetes_namespace_name=~\"multena|tenant2|tenant3\"} |= `message` | json | line_format `{{.message}}` |= `message` | json | unpack | line_format `{{.message}}` [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} |= `message` | json | line_format `{{.message}}` |= `message` | json | unpack | line_format `{{.message}}` [$__interval]))", []string{"tenant2", "tenant3"}, "", errors.New("query contains disallowed namespaces")},
	{"sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} |= `message` | json | line_format `{{.message}}` |= `message` | json | unpack | line_format `{{.message}}` [$__interval]))", []string{"multena", "grafana", "tenant3"}, "sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} |= `message` | json | line_format `{{.message}}` |= `message` | json | unpack | line_format `{{.message}}` [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} |= `message` | json | line_format `{{.message}}` |= `message` | json | unpack | line_format `{{.message}}` [$__interval]))", []string{"multena"}, "", errors.New("query contains disallowed namespaces")},
	{`{kubernetes_pod_name=~"admission-control-5df64f7bbf-66vls"}`, []string{"tenant1", "openshift-logging"}, `{kubernetes_pod_name=~"admission-control-5df64f7bbf-66vls", kubernetes_namespace_name=~"tenant1|openshift-logging"}`, nil},
	{`{kubernetes_pod_name=~"admission-control-5df64f7bbf-66vls"}`, []string{"tenant1"}, `{kubernetes_pod_name=~"admission-control-5df64f7bbf-66vls", kubernetes_namespace_name="tenant1"}`, nil},
	{`{kubernetes_pod_ip="10.128.4.133"} |= "proxy" | json`, []string{"tenant1", "openshift-logging"}, `{kubernetes_pod_ip="10.128.4.133", kubernetes_namespace_name=~"tenant1|openshift-logging"} |= "proxy" | json`, nil},
	{`{kubernetes_pod_ip="10.128.4.133"} |= "proxy" | json`, []string{"tenant1", "openshift-logging", "kube-system", "default"}, `{kubernetes_pod_ip="10.128.4.133", kubernetes_namespace_name=~"tenant1|openshift-logging|kube-system|default"} |= "proxy" | json`, nil},
	{`{kubernetes_pod_ip="10.128.4.133"} |= "proxy" | json`, []string{"openshift-logging"}, `{kubernetes_pod_ip="10.128.4.133", kubernetes_namespace_name="openshift-logging"} |= "proxy" | json`, nil},
	{`sum(rate({kubernetes_namespace_name=~"cert-manager|erhard-pg"} | json | line_format "{{.status_code}}" [$__interval])) > 2`, []string{"cert-manager", "erhard-pg"}, `sum(rate({kubernetes_namespace_name=~"cert-manager|erhard-pg"} | json | line_format "{{.status_code}}" [$__interval])) > 2`, nil},
	{`sum(rate({kubernetes_namespace_name=~"cert-manager|erhard-pg"} | json | line_format "{{.status_code}}" [$__interval])) > 2`, []string{"cert-manager"}, ``, errors.New("query contains disallowed namespaces")},
	{`sum(rate({kubernetes_namespace_name=~"cert-manager|erhard-pg|default"} | json | line_format "{{.status_code}}" [$__interval])) > 2`, []string{"cert-manager|erhard-pg"}, ``, errors.New("query contains disallowed namespaces")},
	{`sum(rate({kubernetes_namespace_name=~"cert-manager|erhard-pg"} | json | line_format "{{.status_code}}" [$__interval])) > 2`, []string{"tenant1"}, "", errors.New("query contains disallowed namespaces")},
	{`sum(rate({kubernetes_namespace_name=~"cert-manager|erhard-pg"} | json | line_format "{{.status_code}}" [$__interval])) > 2`, []string{"different_namespace"}, "", errors.New("query contains disallowed namespaces")},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) - sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", []string{"multena"}, "sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) - sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) + sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", []string{"multena", "grafana"}, "sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) + sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) - sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", []string{"grafana"}, "", errors.New("query contains disallowed namespaces")},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) > sum by(level) (rate({level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", []string{"multena"}, "sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) > sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) - sum by(level) (rate({level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", []string{"multena", "grafana"}, "sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) - sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) == sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", []string{"multena", "grafana"}, "sum by(level) (rate({kubernetes_namespace_name=\"multena|grafana\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) == sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) - sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", []string{"multena", "grafana", "openshift-logging"}, "sum by(level) (rate({kubernetes_namespace_name=\"multena|grafana\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) - sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval])) != sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format `{{.message}}` | json | line_format `{{.message}}` | __error__ = `` [$__interval]))", []string{"multena", "openshift-logging"}, "", errors.New("query contains disallowed namespaces")},
}

func TestEnforceNamespace(t *testing.T) {
	outf, _ := os.Create("output")
	defer outf.Close()
	expf, _ := os.Create("expected")
	defer expf.Close()
	for i, tt := range enforceTests {
		t.Run(tt.query, func(t *testing.T) {
			result, err := enforceNamespaces(tt.query, tt.namespaces)
			//fmt.Println(tt.error, tt.expected)
			//fmt.Println(err, result)
			if err != nil && tt.error == nil {
				_, _ = outf.WriteString(fmt.Sprint(i) + fmt.Sprint(err) + "\n")
				_, _ = expf.WriteString(fmt.Sprint(i) + fmt.Sprint(tt.error) + "\n")
				t.Errorf("expected no error, but got: %v", err)
			}
			if err == nil && tt.error != nil {
				_, _ = outf.WriteString(fmt.Sprint(i) + fmt.Sprint(err) + "\n")
				_, _ = expf.WriteString(fmt.Sprint(i) + fmt.Sprint(tt.error) + "\n")
				t.Errorf("expected error '%v', but got nil", tt.error)
			}
			if err != nil && tt.error != nil && err.Error() != tt.error.Error() {
				_, _ = outf.WriteString(fmt.Sprint(i) + fmt.Sprint(err) + "\n")
				_, _ = expf.WriteString(fmt.Sprint(i) + fmt.Sprint(tt.error) + "\n")
				t.Errorf("expected error '%v', but got '%v'", tt.error, err)
			}
			if result != tt.expected {
				_, _ = outf.WriteString(fmt.Sprint(i) + result + "\n")
				_, _ = expf.WriteString(fmt.Sprint(i) + tt.expected + "\n")
				t.Errorf("expected '%v', but got '%v'", tt.expected, result)
			}
		})
	}
}
