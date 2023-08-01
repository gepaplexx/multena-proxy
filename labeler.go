package main

import (
	"database/sql"
	"go.uber.org/zap"
	"strings"
)

// GetLabelsCM retrieves the namespaces associated with a user and their groups. It merges the
// user's namespaces and the namespaces of each group the user belongs to into a map, avoiding
// duplicates, and returns it. The map keys are the namespaces and the values are all set to true.
func GetLabelsCM(token KeycloakToken) map[string]bool {
	username := token.PreferredUsername
	groups := token.Groups
	var mergedNamespaces map[string]bool
	if len(groups) >= 1 {
		mergedNamespaces = make(map[string]bool, len(username)+len(groups)*len(groups[0]))
	} else {
		mergedNamespaces = make(map[string]bool, len(username))
	}

	for _, namespace := range Cfg.Users[username] {
		mergedNamespaces[namespace] = true
	}
	for _, group := range groups {
		for _, namespace := range Cfg.Groups[group] {
			mergedNamespaces[namespace] = true
		}
	}
	return mergedNamespaces
}

// GetLabelsDB retrieves the namespaces associated with a user from a database. It prepares
// the configured DB query by replacing each question mark with the user's email. Then it queries
// the DB and reads the result into a map. The map keys are the namespaces and the values are all
// set to true. If there are any errors during querying or scanning the result, it logs the error
// and panics. It returns the map of namespaces.
func GetLabelsDB(token KeycloakToken) map[string]bool {
	email := token.Email
	db := DB
	n := strings.Count(Cfg.Db.Query, "?")

	var params []any
	for i := 0; i < n; i++ {
		params = append(params, email)
	}

	res, err := db.Query(Cfg.Db.Query, params...)
	defer func(res *sql.Rows) {
		err := res.Close()
		if err != nil {
			Logger.Panic("Error closing DB result", zap.Error(err))
		}
	}(res)
	if err != nil {
		Logger.Panic("Error while querying database", zap.Error(err))
	}
	labels := make(map[string]bool)
	for res.Next() {
		var label string
		err = res.Scan(&label)
		labels[label] = true
		if err != nil {
			Logger.Panic("Error scanning DB result", zap.Error(err))
		}
	}
	return labels
}
