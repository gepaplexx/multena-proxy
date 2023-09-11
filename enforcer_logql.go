package main

import (
	"fmt"
	"github.com/rs/zerolog/log"
	"strings"

	logqlv2 "github.com/observatorium/api/logql/v2"
	"github.com/prometheus/prometheus/model/labels"
)

type LogQLEnforcer Request

func (r LogQLEnforcer) EnforceQL(query string, tenantLabels map[string]bool, labelMatch string) (string, error) {
	log.Trace().Str("query", query).Msg("enforcing")
	if query == "" {
		operator := "="
		if len(tenantLabels) > 1 {
			operator = "=~"
		}
		return fmt.Sprintf("{%s%s\"%s\"}", labelMatch, operator, strings.Join(MapKeysToArray(tenantLabels), "|")), nil
	}
	log.Trace().Str("query", query).Msg("enforcing")

	expr, err := logqlv2.ParseExpr(query)
	if err != nil {
		return "", err
	}

	errMsg := error(nil)

	expr.Walk(func(expr interface{}) {
		switch labelExpression := expr.(type) {
		case *logqlv2.StreamMatcherExpr:
			matchers, err := matchNamespaceMatchers(labelExpression.Matchers(), tenantLabels, labelMatch)
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
	log.Trace().Str("query", expr.String()).Msg("enforcing")
	return expr.String(), nil
}

// matchNamespaceMatchers takes a slice of label matchers from a LogQL query and a map where keys
// are tenant labels and values are booleans. It checks if the tenant label exists in the matchers,
// and if it does, it verifies that all of its values exist in the tenant labels map. If the tenant
// label does not exist in the matchers, it adds it to the matchers along with all values from the
// tenant labels map. If it encounters an unauthorized namespace during the process, it returns an
// error. If everything goes well, it returns the updated matchers slice and nil error.
func matchNamespaceMatchers(queryMatches []*labels.Matcher, tenantLabels map[string]bool, labelMatch string) ([]*labels.Matcher, error) {
	foundNamespace := false
	for _, match := range queryMatches {
		if match.Name == labelMatch {
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
			Name:  labelMatch,
			Value: strings.Join(MapKeysToArray(tenantLabels), "|"),
		})
	}
	return queryMatches, nil
}
