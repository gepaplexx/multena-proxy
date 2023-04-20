package main

import (
	"fmt"
	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
	"go.uber.org/zap"
	"strings"
)

func logqlEnforcer(query string, tenantLabels []string) (string, error) {
	if query == "" {
		query = "{__name__=~\".+\"}"
	}

	expr, err := logqlv2.ParseExpr(query)
	if err != nil {
		return "", err
	}
	errMsg := error(nil)

	expr.Walk(func(expr interface{}) {
		switch le := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			matchers, err := matchNamespaceMatchers(le.Matchers(), tenantLabels)
			if err != nil {
				errMsg = err
				return
			}
			//Logger.Debug("matchers", zap.Any("matchers", matchers), zap.Int("line", 156))
			le.SetMatchers(matchers)
		default:
			// Do nothing
		}
	})
	if errMsg != nil {
		Logger.Debug("error", zap.Error(errMsg), zap.Int("line", 164))
		return "", errMsg
	}
	Logger.Debug("expr", zap.String("expr", expr.String()), zap.String("TL", strings.Join(tenantLabels, "|")), zap.Int("line", 168))
	return expr.String(), nil
}

func matchNamespaceMatchers(qm []*labels.Matcher, tl []string) ([]*labels.Matcher, error) {
	// Check if any matchers in list1 are not in list2
	foundNamespace := false
	for _, m1 := range qm {
		if m1.Name == "kubernetes_namespace_name" {
			foundNamespace = true
			vs := strings.Split(m1.Value, "|")
			if len(vs) > 1 {
				return nil, fmt.Errorf("temporary not supported, please use only one namespace")

			}
			allowed, label := allStringsInList(vs, tl)
			if !allowed {
				return nil, fmt.Errorf("unauthorized labels %s", label)
			}
			//Logger.Debug("values", zap.String("values", m1.Value), zap.Int("line", 247))
		}
	}
	if !foundNamespace {
		matchType := labels.MatchEqual
		if len(tl) > 1 {
			return nil, fmt.Errorf("temporary not supported, please use only one namespace")
			//matchType = labels.MatchRegexp
		}
		qm = append(qm, &labels.Matcher{Type: matchType, Name: "kubernetes_namespace_name", Value: strings.Join(tl, "|")})
	}

	return qm, nil

}

func allStringsInList(list1, list2 []string) (bool, string) {
	for _, str1 := range list1 {
		found := false
		for _, str2 := range list2 {
			if str1 == str2 {
				found = true
				break
			}
		}
		if !found {
			return false, str1
		}
	}
	return true, ""
}
