package main

import (
	"errors"
	"fmt"
	"go.uber.org/zap"
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
	{`sum(rate({level="error"} [$__interval]))`, []string{"tenant1", "openshift-logging"}, `sum(rate({level="error", kubernetes_namespace_name=~"tenant1|openshift-logging"}[$__interval]))`, nil},
	{`sum(rate({level="error", kubernetes_host="worker21"} [$__interval]))`, []string{"tenant1", "openshift-logging"}, `sum(rate({level="error", kubernetes_host="worker21", kubernetes_namespace_name=~"tenant1|openshift-logging"}[$__interval]))`, nil},
	{`sum(rate({level="error", kubernetes_host="worker21", kubernetes_namespace_name="gepaplexx-cicd-tools"} [$__interval]))`, []string{"tenant1", "gepaplexx-cicd-tools"}, `sum(rate({level="error", kubernetes_host="worker21", kubernetes_namespace_name="gepaplexx-cicd-tools"}[$__interval]))`, nil},
	{`sum(rate({level="error", kubernetes_host="worker21", kubernetes_namespace_name="gepaplexx-cicd-tools"} [$__interval]))`, []string{"tenant1", "tenant2"}, ``, errors.New("unauthorized labels gepaplexx-cicd-tools")},
	{`sum(rate({level="error", kubernetes_host="worker21", kubernetes_namespace_name=~"gepaplexx-cicd-tools|tenant1"} [$__interval]))`, []string{"tenant1", "gepaplexx-cicd-tools", "tenant3", "tenant_blubb"}, ``, errors.New("temporary not supported, please use only one namespace")},
	{"sum by(level) (rate(({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} |= \"message\" | json | line_format \"{{.message}}\" |= \"message\" | json | unpack | line_format \"{{.message}}\") [$__interval]))", []string{"multena"}, "sum by(level) (rate(({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} |= \"message\" | json | line_format \"{{.message}}\" |= \"message\" | json | unpack | line_format \"{{.message}}\") [$__interval]))", nil},
	{"sum by(level) (rate(({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} |= \"message\" | json | line_format \"{{.message}}\" |= \"message\" | json | unpack | line_format \"{{.message}}\") [$__interval]))", []string{"multena", "tenant2"}, "sum by(level) (rate(({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} |= \"message\" | json | line_format \"{{.message}}\" |= \"message\" | json | unpack | line_format \"{{.message}}\") [$__interval]))", nil},
	{"sum by(level) (rate({level=~\"error|default\"} |= \"message\" | json | line_format \"{{.message}}\" |= \"message\" | json | unpack | line_format \"{{.message}}\" [$__interval]))", []string{"multena", "tenant2", "tenant3"}, "sum by(level) (rate(({level=~\"error|default\", kubernetes_namespace_name=~\"multena|tenant2|tenant3\"} |= \"message\" | json | line_format \"{{.message}}\" |= \"message\" | json | unpack | line_format \"{{.message}}\") [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} |= \"message\" | json | line_format \"{{.message}}\" |= \"message\" | json | unpack | line_format \"{{.message}}\" [$__interval]))", []string{"tenant2", "tenant3"}, "", errors.New("unauthorized labels multena")},
	{"sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} |= \"message\" | json | line_format \"{{.message}}\" |= \"message\" | json | unpack | line_format \"{{.message}}\" [$__interval]))", []string{"multena", "grafana", "tenant3"}, "sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} |= \"message\" | json | line_format \"{{.message}}\" |= \"message\" | json | unpack | line_format \"{{.message}}\" [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} |= \"message\" | json | line_format \"{{.message}}\" |= \"message\" | json | unpack | line_format \"{{.message}}\" [$__interval]))", []string{"multena"}, "", errors.New("unauthorized labels grafana")},
	{`{kubernetes_pod_name=~"admission-control-5df64f7bbf-66vls"}`, []string{"tenant1", "openshift-logging"}, `{kubernetes_pod_name=~"admission-control-5df64f7bbf-66vls", kubernetes_namespace_name=~"tenant1|openshift-logging"}`, nil},
	{`{kubernetes_pod_name=~"admission-control-5df64f7bbf-66vls"}`, []string{"tenant1"}, `{kubernetes_pod_name=~"admission-control-5df64f7bbf-66vls", kubernetes_namespace_name="tenant1"}`, nil},
	{`{kubernetes_pod_ip="10.128.4.133"} |= "proxy" | json`, []string{"tenant1", "openshift-logging"}, `{kubernetes_pod_ip="10.128.4.133", kubernetes_namespace_name=~"tenant1|openshift-logging"} |= "proxy" | json`, nil},
	{`{kubernetes_pod_ip="10.128.4.133"} |= "proxy" | json`, []string{"tenant1", "openshift-logging", "kube-system", "default"}, `{kubernetes_pod_ip="10.128.4.133", kubernetes_namespace_name=~"tenant1|openshift-logging|kube-system|default"} |= "proxy" | json`, nil},
	{`{kubernetes_pod_ip="10.128.4.133"} |= "proxy" | json`, []string{"openshift-logging"}, `{kubernetes_pod_ip="10.128.4.133", kubernetes_namespace_name="openshift-logging"} |= "proxy" | json`, nil},
	{`sum(rate({kubernetes_namespace_name=~"cert-manager|erhard-pg"} | json | line_format "{{.status_code}}" [$__interval])) > 2`, []string{"cert-manager", "erhard-pg"}, `sum(rate({kubernetes_namespace_name=~"cert-manager|erhard-pg"} | json | line_format "{{.status_code}}" [$__interval])) > 2`, nil},
	{`sum(rate({kubernetes_namespace_name=~"cert-manager|erhard-pg"} | json | line_format "{{.status_code}}" [$__interval])) > 2`, []string{"cert-manager"}, ``, errors.New("temporary not supported, please use only one namespace")},
	{`sum(rate({kubernetes_namespace_name=~"cert-manager|erhard-pg|default"} | json | line_format "{{.status_code}}" [$__interval])) > 2`, []string{"cert-manager|erhard-pg"}, ``, errors.New("temporary not supported, please use only one namespace")},
	{`sum(rate({kubernetes_namespace_name=~"cert-manager|erhard-pg"} | json | line_format "{{.status_code}}" [$__interval])) > 2`, []string{"tenant1"}, "", errors.New("temporary not supported, please use only one namespace")},
	{`sum(rate({kubernetes_namespace_name=~"cert-manager|erhard-pg"} | json | line_format "{{.status_code}}" [$__interval])) > 2`, []string{"different_namespace"}, "", errors.New("temporary not supported, please use only one namespace")},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval])) - sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval]))", []string{"multena"}, "sum by(level) (rate(({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__=\"\") [$__interval])) - sum by(level) (rate(({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__=\"\") [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval])) + sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval]))", []string{"multena", "grafana"}, "sum by(level) (rate(({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__=\"\") [$__interval])) + sum by(level) (rate(({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__=\"\") [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval])) - sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval]))", []string{"grafana"}, "", errors.New("unauthorized labels multena")},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval])) > sum by(level) (rate({level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval]))", []string{"multena"}, "sum by(level) (rate(({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__=\"\") [$__interval])) > sum by(level) (rate(({level=~\"error|default\", kubernetes_namespace_name=\"multena\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__=\"\") [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval])) - sum by(level) (rate({level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval]))", []string{"multena", "grafana"}, "sum by(level) (rate(({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__=\"\") [$__interval])) - sum by(level) (rate(({level=~\"error|default\", kubernetes_namespace_name=~\"multena|grafana\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__=\"\") [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval])) == sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval]))", []string{"multena", "grafana"}, "sum by(level) (rate({kubernetes_namespace_name=\"multena|grafana\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval])) == sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval])) - sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval]))", []string{"multena", "grafana", "openshift-logging"}, "sum by(level) (rate({kubernetes_namespace_name=\"multena|grafana\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval])) - sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval]))", nil},
	{"sum by(level) (rate({kubernetes_namespace_name=~\"multena|grafana\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval])) != sum by(level) (rate({kubernetes_namespace_name=\"multena\", level=~\"error|default\"} | json | line_format \"{{.message}}\" | json | line_format \"{{.message}}\" | __error__ = \"\" [$__interval]))", []string{"multena", "openshift-logging"}, "", errors.New("query contains disallowed namespaces")},
}

func TestEnforceNamespace(t *testing.T) {
	Logger.Debug("-------- starting test ---------")
	outf, _ := os.Create("output")
	defer func(outf *os.File) {
		err := outf.Close()
		if err != nil {
			Logger.Error("error closing file: %v", zap.Error(err))
		}
	}(outf)
	expf, _ := os.Create("expected")
	defer func(expf *os.File) {
		err := expf.Close()
		if err != nil {
			Logger.Error("error closing file: %v", zap.Error(err))
		}
	}(expf)
	for i, tt := range enforceTests {
		t.Run(tt.query, func(t *testing.T) {
			result, err := logqlEnforcer(tt.query, tt.namespaces)
			write := false
			if fmt.Sprintf("%s", err) == "temporary not supported, please use only one namespace" {
				return // skip test
			}
			if err != nil && tt.error == nil {
				write = true
				t.Errorf("expected no error, but got: %v", err)
			}
			if err == nil && tt.error != nil {
				write = true
				t.Errorf("expected error '%v', but got nil", tt.error)
			}
			if err != nil && tt.error != nil && err.Error() != tt.error.Error() {
				write = true
				t.Errorf("expected error '%v', but got '%v'", tt.error, err)
			}
			if result != tt.expected {
				write = true
				t.Errorf("expected '%v', but got '%v'", tt.expected, result)
			}

			if write {
				_, _ = outf.WriteString(fmt.Sprint(i) + fmt.Sprint(err) + result + "\n")
				_, _ = expf.WriteString(fmt.Sprint(i) + fmt.Sprint(tt.error) + tt.expected + "\n")
			}
		})
	}
}
