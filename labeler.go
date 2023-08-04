package main

import (
	"database/sql"
	"go.uber.org/zap"
	"strings"
)

// GetLabelsCM function extracts the namespaces associated with a user and their groups
// from the configuration file.
// It takes a KeycloakToken and returns a map where keys are namespaces and
// values are booleans indicating their presence.
// Note: CM stands for ConfigMap, indicating that this function retrieves labels
// from the configuration map.
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

// GetLabelsDB function queries a database to get the labels associated with a user
// using their email. It makes a query to the database using the email from the token,
// collects the labels returned by the query and returns them as a map where the keys are labels
// and values are booleans indicating their presence.
// Note: DB stands for DataBase, indicating that this function retrieves labels from a database.
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
