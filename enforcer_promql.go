package main

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	enforcer "github.com/prometheus-community/prom-label-proxy/injectproxy"
	"github.com/prometheus/prometheus/model/labels"
	"github.com/prometheus/prometheus/promql/parser"
)

// PromQLEnforcer is a struct with methods to enforce specific rules on Prometheus Query Language (PromQL) queries.
type PromQLEnforcer struct{}

// Enforce enhances a given PromQL query string with additional label matchers,
// ensuring that the query complies with the allowed tenant labels and specified label match.
// It returns the enhanced query or an error if the query cannot be parsed or is not compliant.
func (PromQLEnforcer) Enforce(query string, allowedTenantLabels map[string]bool, labelMatch string) (string, error) {
	log.Trace().Str("function", "enforcer").Str("query", query).Msg("input")
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

// extractLabelsAndValues parses a PromQL expression and extracts labels and their values.
// It returns a map where keys are label names and values are corresponding label values.
// An error is returned if the expression cannot be parsed.
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

// enforceLabels checks if provided query labels comply with allowed tenant labels and a specified label match.
// If the labels comply, it returns them (or all allowed tenant labels if not specified in the query) and nil.
// If not, it returns an error indicating the non-compliant label.
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

// checkLabels validates if query labels are present in the allowed tenant labels and returns them.
// If a query label is not allowed, it returns false and the non-compliant label.
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

func createEnforcer(tenantLabels []string, labelMatch string) *enforcer.PromQLEnforcer {
	var matchType labels.MatchType
	if len(tenantLabels) > 1 {
		matchType = labels.MatchRegexp
	} else {
		matchType = labels.MatchEqual
	}

	return enforcer.NewPromQLEnforcer(true, &labels.Matcher{
		Name:  labelMatch,
		Type:  matchType,
		Value: strings.Join(tenantLabels, "|"),
	})
}
