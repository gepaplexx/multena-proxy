package main

import (
	"fmt"
	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
	"go.uber.org/zap"
	"strings"
	"time"
)

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
		Logger.Debug("error", zap.Error(errMsg), zap.Int("line", 164))
		return "", errMsg
	}
	Logger.Debug("expr", zap.String("expr", expr.String()), zap.Any("tl", tenantLabels))
	Logger.Info("long term query collection processed", zap.String("ltqcp", expr.String()), zap.Any("tl", tenantLabels), zap.Time("time", currentTime))
	return expr.String(), nil
}

func matchNamespaceMatchers(queryMatches []*labels.Matcher, tenantLabels map[string]bool) ([]*labels.Matcher, error) {
	foundNamespace := false
	for _, match := range queryMatches {
		if match.Name == "kubernetes_namespace_name" {
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
			Name:  "kubernetes_namespace_name",
			Value: strings.Join(MapKeysToArray(tenantLabels), "|"),
		})
	}
	return queryMatches, nil
}
