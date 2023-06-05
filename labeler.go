package main

import (
	"database/sql"
	"go.uber.org/zap"
	"strings"
)

func GetLabelsCM(username string, groups []string) map[string]bool {
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

func GetLabelsFromDB(email string) map[string]bool {
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
