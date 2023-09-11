package main

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"strings"

	enforcer "github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

type PromQLEnforcer Request

func (pqr PromQLEnforcer) EnforceQL(query string, allowedTenantLabels map[string]bool, labelMatch string) (string, error) {
	log.Trace().Str("function", "enforcer").Str("query", query).Msg("enforcing")
	if query == "" {
		operator := "="
		if len(allowedTenantLabels) > 1 {
			operator = "=~"
		}
		query = fmt.Sprintf("{%s%s\"%s\"}",
			labelMatch,
			operator,
			strings.Join(MapKeysToArray(allowedTenantLabels),
				"|"))
	}
	log.Trace().Str("function", "enforcer").Str("query", query).Msg("enforcing")
	expr, err := parser.ParseExpr(query)
	if err != nil {
		return "", err
	}

	queryLabels, err := extractLabelsAndValues(expr)
	if err != nil {
		return "", err
	}

	tenantLabels, err := enforceLabels(queryLabels, allowedTenantLabels, labelMatch)
	if err != nil {
		return "", err
	}

	labelEnforcer := createEnforcer(tenantLabels, labelMatch)
	err = labelEnforcer.EnforceNode(expr)
	if err != nil {
		return "", err
	}
	log.Trace().Str("function", "enforcer").Str("query", expr.String()).Msg("enforcing")
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
func enforceLabels(queryLabels map[string]string, allowedTenantLabels map[string]bool, labelMatch string) ([]string, error) {
	if _, ok := queryLabels[labelMatch]; ok {
		ok, tenantLabels := checkLabels(queryLabels, allowedTenantLabels, labelMatch)
		if !ok {
			return nil, fmt.Errorf("user not allowed with namespace %s", tenantLabels[0])
		}
		return tenantLabels, nil
	}

	return MapKeysToArray(allowedTenantLabels), nil
}

// checkLabels checks if all query labels are within the allowed tenant labels.
// Returns a boolean indicating success, and the checked labels.
func checkLabels(queryLabels map[string]string, allowedTenantLabels map[string]bool, labelMatch string) (bool, []string) {
	splitQueryLabels := strings.Split(queryLabels[labelMatch], "|")
	for _, queryLabel := range splitQueryLabels {
		_, ok := allowedTenantLabels[queryLabel]
		if !ok {
			return false, []string{queryLabel}
		}
	}
	return true, splitQueryLabels
}

// createEnforcer creates and returns a label enforcer with a matcher containing tenant labels.
func createEnforcer(tenantLabels []string, labelMatch string) *enforcer.Enforcer {
	var matchType labels.MatchType
	if len(tenantLabels) > 1 {
		matchType = labels.MatchRegexp
	} else {
		matchType = labels.MatchEqual
	}

	return enforcer.NewEnforcer(true, &labels.Matcher{
		Name:  labelMatch,
		Type:  matchType,
		Value: strings.Join(tenantLabels, "|"),
	})
}
