package main

import (
	"fmt"
	"strings"
	"time"

	enforcer "github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"go.uber.org/zap"
)

type PromQLRequest Request

func (pqr PromQLRequest) EnforceQL(query string, allowedTenantLabels map[string]bool) (string, error) {
	currentTime := time.Now()
	if query == "" {
		operator := "="
		if len(allowedTenantLabels) > 1 {
			operator = "=~"
		}
		query = fmt.Sprintf("{%s%s\"%s\"}",
			Cfg.Thanos.TenantLabel,
			operator,
			strings.Join(MapKeysToArray(allowedTenantLabels),
				"|"))
	}
	Logger.Debug("Start promqlEnforcer", zap.String("query", query), zap.Time("time", currentTime))
	expr, err := parser.ParseExpr(query)
	if err != nil {
		Logger.Error("error",
			zap.Error(err),
			zap.String("info", "parsing query"))
		return "", err
	}

	Logger.Info("long term query collection",
		zap.String("ltqc", expr.String()),
		zap.Time("time", currentTime))

	queryLabels, err := extractLabelsAndValues(expr)
	if err != nil {
		Logger.Error("error",
			zap.Error(err),
			zap.String("info", "extracting labels"))
		return "", err
	}

	tenantLabels, err := enforceLabels(queryLabels, allowedTenantLabels)
	if err != nil {
		Logger.Error("error",
			zap.Error(err),
			zap.String("info", "enforcing labels"))
		return "", err
	}

	labelEnforcer := createEnforcer(tenantLabels)
	err = labelEnforcer.EnforceNode(expr)
	if err != nil {
		Logger.Error("error",
			zap.Error(err))
		return "", err
	}

	Logger.Debug("expr",
		zap.String("expr", expr.String()),
		zap.String("tl", strings.Join(tenantLabels, "|")))
	Logger.Info("long term query collection processed",
		zap.String("ltqcp", expr.String()),
		zap.Time("time", currentTime))
	return expr.String(), nil
}

// extractLabelsAndValues takes a PromQL expression and traverses the expression tree to extract
// all labels and their corresponding values. It returns a map where keys are labels and values
// are their corresponding values. If an error occurs during the process, it returns an error.
func extractLabelsAndValues(expr parser.Expr) (map[string]string, error) {
	l := make(map[string]string)
	parser.Inspect(expr, func(node parser.Node, path []parser.Node) error {
		if vector, ok := node.(*parser.VectorSelector); ok {
			for _, matcher := range vector.LabelMatchers {
				l[matcher.Name] = matcher.Value
			}
		}
		return nil
	})
	return l, nil
}

// enforceLabels takes a map where keys are labels from a query and their values, and a map where keys
// are allowed tenant labels and values are booleans. It checks if the tenant label exists in the
// query labels. If it does, it verifies that all of its values exist in the allowed tenant labels map.
// If the tenant label does not exist in the query labels, it returns all values from the allowed tenant
// labels map. If it encounters a tenant that is not allowed during the process, it returns an error.
func enforceLabels(queryLabels map[string]string, allowedTenantLabels map[string]bool) ([]string, error) {
	if _, ok := queryLabels[Cfg.Thanos.TenantLabel]; ok {
		ok, tenantLabels := checkLabels(queryLabels, allowedTenantLabels)
		if !ok {
			return nil, fmt.Errorf("user not allowed with namespace %s", tenantLabels[0])
		}
		return tenantLabels, nil
	}

	return MapKeysToArray(allowedTenantLabels), nil
}

// checkLabels checks if all query labels are within the allowed tenant labels.
// Returns a boolean indicating success, and the checked labels.
func checkLabels(queryLabels map[string]string, allowedTenantLabels map[string]bool) (bool, []string) {
	splitQueryLabels := strings.Split(queryLabels[Cfg.Thanos.TenantLabel], "|")
	for _, queryLabel := range splitQueryLabels {
		_, ok := allowedTenantLabels[queryLabel]
		if !ok {
			return false, []string{queryLabel}
		}
	}
	return true, splitQueryLabels
}

// createEnforcer creates and returns a label enforcer with a matcher containing tenant labels.
func createEnforcer(tenantLabels []string) *enforcer.Enforcer {
	var matchType labels.MatchType
	if len(tenantLabels) > 1 {
		matchType = labels.MatchRegexp
	} else {
		matchType = labels.MatchEqual
	}

	return enforcer.NewEnforcer(true, &labels.Matcher{
		Name:  Cfg.Thanos.TenantLabel,
		Type:  matchType,
		Value: strings.Join(tenantLabels, "|"),
	})
}
