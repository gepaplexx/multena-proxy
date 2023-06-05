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
		//le defines the label expression
		switch le := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			matchers, err := matchNamespaceMatchers(le.Matchers(), tenantLabels)
			if err != nil {
				errMsg = err
				return
			}
			le.SetMatchers(matchers)
		default:
			// Do nothing
		}
	})
	if errMsg != nil {
		Logger.Debug("error", zap.Error(errMsg), zap.Int("line", 164))
		return "", errMsg
	}
	Logger.Debug("expr", zap.String("expr", expr.String()), zap.Any("TL", tenantLabels))
	Logger.Info("long term query collection processed", zap.String("ltqcp", expr.String()), zap.Any("tl", tenantLabels), zap.Time("time", currentTime))
	return expr.String(), nil
}

func matchNamespaceMatchers(qm []*labels.Matcher, tl map[string]bool) ([]*labels.Matcher, error) {
	// Check if any matchers in list1 are not in list2
	foundNamespace := false
	for _, m1 := range qm {
		if m1.Name == "kubernetes_namespace_name" {
			foundNamespace = true
			qls := strings.Split(m1.Value, "|")
			for _, ql := range qls {
				_, ok := tl[ql]
				if !ok {
					return nil, fmt.Errorf("unauthorized namespace %s", ql)
				}
			}
		}
	}
	if !foundNamespace {
		matchType := labels.MatchEqual
		if len(tl) > 1 {
			matchType = labels.MatchRegexp
		}

		qm = append(qm, &labels.Matcher{
			Type:  matchType,
			Name:  "kubernetes_namespace_name",
			Value: strings.Join(MapKeysToArray(tl), "|"),
		})
	}
	return qm, nil
}
