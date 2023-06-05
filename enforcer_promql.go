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

func promqlEnforcer(query string, allowedTenantLabels map[string]bool) (string, error) {
	currentTime := time.Now()
	expr, err := parser.ParseExpr(query)
	if err != nil {
		Logger.Error("error", zap.Error(err), zap.String("info", "parsing query"))
		return "", err
	}
	Logger.Info("long term query collection", zap.String("ltqc", expr.String()), zap.Time("time", currentTime))

	queryLabels, err := extractLabelsAndValues(expr)
	if err != nil {
		Logger.Error("error", zap.Error(err), zap.String("info", "extracting labels"))
		return "", err
	}

	tenantLabels, err := enforceLabels(queryLabels, allowedTenantLabels)
	if err != nil {
		Logger.Error("error", zap.Error(err), zap.String("info", "enforcing labels"))
		return "", err
	}

	labelEnforcer := createEnforcer(tenantLabels)
	err = labelEnforcer.EnforceNode(expr)
	if err != nil {
		Logger.Debug("error", zap.Error(err))
		return "", err
	}

	Logger.Debug("expr", zap.String("expr", expr.String()), zap.String("tl", strings.Join(tenantLabels, "|")))
	Logger.Info("long term query collection processed", zap.String("ltqcp", expr.String()), zap.Time("time", currentTime))
	return expr.String(), nil
}

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
