package main

import (
	"fmt"
	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
	"go.uber.org/zap"
	"strings"
	"time"
)

// logqlEnforcer enforces tenant restrictions on a given LogQL query by modifying the query
// to include only those labels that are allowed for a particular tenant. It takes a LogQL query
// as a string and a map where keys are tenant labels and values are booleans.
// If the query is empty, it is set to "{__name__=~\".+\"}".
// The function then parses the LogQL query and walks through the parsed query to match and enforce
// tenant label restrictions.
// It returns the enforced query as a string and an error if any occurs during the process.
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

// matchNamespaceMatchers takes a slice of label matchers from a LogQL query and a map where keys
// are tenant labels and values are booleans. It checks if the tenant label exists in the matchers,
// and if it does, it verifies that all of its values exist in the tenant labels map. If the tenant
// label does not exist in the matchers, it adds it to the matchers along with all values from the
// tenant labels map. If it encounters an unauthorized namespace during the process, it returns an
// error. If everything goes well, it returns the updated matchers slice and nil error.
func matchNamespaceMatchers(queryMatches []*labels.Matcher, tenantLabels map[string]bool) ([]*labels.Matcher, error) {
	foundNamespace := false
	for _, match := range queryMatches {
		if match.Name == Cfg.Loki.TenantLabel {
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
			Name:  Cfg.Loki.TenantLabel,
			Value: strings.Join(MapKeysToArray(tenantLabels), "|"),
		})
	}
	return queryMatches, nil
}
