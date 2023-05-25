package main

import (
	"database/sql"
	"go.uber.org/zap"
	"strings"
)

func GetLabelsCM(username string, groups []string) map[string]bool {
	mergedNamespaces := make(map[string]bool, len(username)+len(groups)<<2)
	for _, ns := range C.Users[username] {
		mergedNamespaces[ns] = true
	}
	for _, g := range groups {
		for _, ns := range C.Groups[g] {
			mergedNamespaces[ns] = true
		}
	}
	return mergedNamespaces
}

func GetLabelsFromDB(email string) map[string]bool {
	db := DB
	n := strings.Count(C.Db.Query, "?")

	var params []any
	for i := 0; i < n; i++ {
		params = append(params, email)
	}

	res, err := db.Query(C.Db.Query, params...)
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
