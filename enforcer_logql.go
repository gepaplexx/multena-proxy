package main

import (
	"fmt"
	"strings"

	"github.com/rs/zerolog/log"

	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
)

// LogQLEnforcer manipulates and enforces tenant isolation on LogQL queries.
type LogQLEnforcer struct{}

// Enforce modifies a LogQL query string to enforce tenant isolation based on provided tenant labels and a label match string.
// If the input query is empty, a new query is constructed to match provided tenant labels.
// If the input query is non-empty, it is parsed and modified to ensure tenant isolation.
// Returns the modified query or an error if parsing or modification fails.
func (LogQLEnforcer) Enforce(query string, tenantLabels map[string]bool, labelMatch string) (string, error) {
	log.Trace().Str("function", "enforcer").Str("query", query).Msg("input")
	if query == "" {
		operator := "="
		if len(tenantLabels) > 1 {
			operator = "=~"
		}
		query = fmt.Sprintf("{%s%s\"%s\"}", labelMatch, operator, strings.Join(MapKeysToArray(tenantLabels), "|"))
		log.Trace().Str("function", "enforcer").Str("query", query).Msg("enforcing")
		return query, nil
	}
	log.Trace().Str("function", "enforcer").Str("query", query).Msg("enforcing")

	expr, err := logqlv2.ParseExpr(query)
	if err != nil {
		return "", err
	}

	errMsg := error(nil)

	expr.Walk(func(expr interface{}) {
		switch labelExpression := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			matchers, err := MatchTenantLabelMatchers(labelExpression.Matchers(), tenantLabels, labelMatch)
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
		return "", errMsg
	}
	log.Trace().Str("function", "enforcer").Str("query", expr.String()).Msg("enforcing")
	return expr.String(), nil
}

// MatchTenantLabelMatchers ensures tenant label matchers in a LogQL query adhere to provided tenant labels.
// It verifies that the tenant label exists in the query matchers, validating or modifying its values based on tenantLabels.
// If the tenant label is absent in the matchers, it's added along with all values from tenantLabels.
// Returns an error for an unauthorized namespace and nil on success.
func MatchTenantLabelMatchers(queryMatches []*labels.Matcher, tenantLabels map[string]bool, labelMatch string) ([]*labels.Matcher, error) {
	foundTenantLabel := false
	for _, match := range queryMatches {
		if match.Name == labelMatch {
			foundTenantLabel = true
			queryLabels := strings.Split(match.Value, "|")
			for _, queryLabel := range queryLabels {
				_, ok := tenantLabels[queryLabel]
				if !ok {
					return nil, fmt.Errorf("unauthorized label %s", queryLabel)
				}
			}
		}
	}
	if !foundTenantLabel {
		matchType := labels.MatchEqual
		if len(tenantLabels) > 1 {
			matchType = labels.MatchRegexp
		}

		queryMatches = append(queryMatches, &labels.Matcher{
			Type:  matchType,
			Name:  labelMatch,
			Value: strings.Join(MapKeysToArray(tenantLabels), "|"),
		})
	}
	return queryMatches, nil
}
