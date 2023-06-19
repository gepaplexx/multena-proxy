package main

import (
	"fmt"
	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
	"go.uber.org/zap"
	"strings"
	"time"
)

// logqlEnforcer enforces the LogQL query based on tenant labels. If the query is empty,
// it sets a default query. It parses the provided query and walks through the expressions,
// looking for stream match expressions. If a stream match expression is found, it updates
// the matchers to match the tenant's labels. If no namespace matchers are found in the query,
// it returns an error (namespace should be set in matchNamespaceMatcher therefore it's a validation).
// If all is well, it logs the processed query and returns it.
func logqlEnforcer(query string, tenantLabels map[string]bool) (string, error) {
	currentTime := time.Now()
	if query == "" {
		query = "{__name__=~\".+\"}"
	}

	expr, err := logqlv2.ParseExpr(query)
	if err != nil {
		return "", err
	}
	Logger.Info("long term query collection", zap.String("ltqc", expr.String()), zap.Time("time", currentTime))

	errMsg := error(nil)

	expr.Walk(func(expr interface{}) {
		switch labelExpression := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			matchers, err := matchNamespaceMatchers(labelExpression.Matchers(), tenantLabels)
			if err != nil {
				errMsg = err
				return
			}
			labelExpression.SetMatchers(matchers)
		default:
			// Do nothing
		}
	})
	if errMsg != nil {
		Logger.Error("error", zap.Error(errMsg), zap.Int("line", 164))
		return "", errMsg
	}
	Logger.Debug("expr", zap.String("expr", expr.String()), zap.Any("tl", tenantLabels))
	Logger.Info("long term query collection processed", zap.String("ltqcp", expr.String()), zap.Any("tl", tenantLabels), zap.Time("time", currentTime))
	return expr.String(), nil
}

// matchNamespaceMatchers updates matchers based on tenantLabels. If the match name equals
// the configured Loki tenant label, it checks if the match value exists in tenantLabels.
// If a match value does not exist in tenantLabels, it returns an error. If no namespace
// matchers are found in queryMatches, it adds a matcher that matches tenantLabels.
// It returns the updated matchers.
func matchNamespaceMatchers(queryMatches []*labels.Matcher, tenantLabels map[string]bool) ([]*labels.Matcher, error) {
	foundNamespace := false
	for _, match := range queryMatches {
		if match.Name == Cfg.Proxy.TenantLabels.Loki {
			foundNamespace = true
			queryLabels := strings.Split(match.Value, "|")
			for _, queryLabel := range queryLabels {
				_, ok := tenantLabels[queryLabel]
				if !ok {
					return nil, fmt.Errorf("unauthorized namespace %s", queryLabel)
				}
			}
		}
	}
	if !foundNamespace {
		matchType := labels.MatchEqual
		if len(tenantLabels) > 1 {
			matchType = labels.MatchRegexp
		}

		queryMatches = append(queryMatches, &labels.Matcher{
			Type:  matchType,
			Name:  Cfg.Proxy.TenantLabels.Loki,
			Value: strings.Join(MapKeysToArray(tenantLabels), "|"),
		})
	}
	return queryMatches, nil
}
