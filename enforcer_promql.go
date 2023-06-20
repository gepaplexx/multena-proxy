package main

import (
	"fmt"
	enforcer "github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
	"go.uber.org/zap"
	"strings"
	"time"
)

// promqlEnforcer enforces the PromQL query based on allowed tenant labels. It parses the
// provided query, extracts the labels, and enforces the labels. Then, it enforces the labels
// on the parsed expression using an Enforcer. It logs the processed query and returns it.
// If there are any errors during parsing, extracting, enforcing or enforcing node, it logs
// the error and returns it.
func promqlEnforcer(query string, allowedTenantLabels map[string]bool) (string, error) {
	currentTime := time.Now()
	if query == "" {
		operator := "="
		if len(allowedTenantLabels) > 1 {
			operator = "=~"
		}
		query = fmt.Sprintf("{%s%s\"%s\"}",
			Cfg.Proxy.TenantLabels.Thanos,
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

// extractLabelsAndValues inspects a given expression and extracts label names and values
// from vector selectors. It returns a map of label names to their corresponding values.
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

// enforceLabels enforces the given query labels based on allowed tenant labels. If a label
// exists in the query that matches the Thanos tenant label in the config, it checks the label
// against allowed tenant labels. If the check fails, it returns an error. If no label matches
// the Thanos tenant label, it returns all allowed tenant labels.
func enforceLabels(queryLabels map[string]string, allowedTenantLabels map[string]bool) ([]string, error) {
	if _, ok := queryLabels[Cfg.Proxy.TenantLabels.Thanos]; ok {
		ok, tenantLabels := checkLabels(queryLabels, allowedTenantLabels)
		if !ok {
			return nil, fmt.Errorf("user not allowed with namespace %s", tenantLabels[0])
		}
		return tenantLabels, nil
	}

	return MapKeysToArray(allowedTenantLabels), nil
}

// checkLabels checks query labels against allowed tenant labels. If a query label does not exist
// in allowed tenant labels, it returns false along with the query label. If all query labels exist
// in allowed tenant labels, it returns true along with the query labels.
func checkLabels(queryLabels map[string]string, allowedTenantLabels map[string]bool) (bool, []string) {
	splitQueryLabels := strings.Split(queryLabels[Cfg.Proxy.TenantLabels.Thanos], "|")
	for _, queryLabel := range splitQueryLabels {
		_, ok := allowedTenantLabels[queryLabel]
		if !ok {
			return false, []string{queryLabel}
		}
	}
	return true, splitQueryLabels
}

// createEnforcer creates a new Enforcer with a matcher that matches tenant labels. If there are
// multiple tenant labels, it uses a regexp match type, else it uses an equal match type. The matcher
// name is set to the Thanos tenant label in the config and the value is set to the tenant labels
// joined by a pipe character.
func createEnforcer(tenantLabels []string) *enforcer.Enforcer {
	var matchType labels.MatchType
	if len(tenantLabels) > 1 {
		matchType = labels.MatchRegexp
	} else {
		matchType = labels.MatchEqual
	}

	return enforcer.NewEnforcer(true, &labels.Matcher{
		Name:  Cfg.Proxy.TenantLabels.Thanos,
		Type:  matchType,
		Value: strings.Join(tenantLabels, "|"),
	})
}
