package main

import (
	"database/sql"
	"go.uber.org/zap"
	"os"
	"strings"
)

func GetLabelsCM(username string, groups []string) []string {
	labels := C.Users[username]
	for _, group := range groups {
		labels = append(labels, C.Groups[strings.ToLower(group)]...)
	}
	return labels
}

func GetLabelsFromDB(email string) []string {
	db := DB
	stmt := os.Getenv("LABEL_DB_QUERY")
	n := strings.Count(stmt, "?")

	var params []any
	for i := 0; i < n; i++ {
		params = append(params, email)
	}

	res, err := db.Query(stmt, params...)
	defer func(res *sql.Rows) {
		err := res.Close()
		if err != nil {
			Logger.Panic("Error closing DB result", zap.Error(err))
		}
	}(res)
	if err != nil {
		Logger.Panic("Error while querying database", zap.Error(err))
	}
	var labels []string
	for res.Next() {
		var label string
		err = res.Scan(&label)
		labels = append(labels, label)
		if err != nil {
			Logger.Panic("Error scanning DB result", zap.Error(err))
		}
	}
	return labels
}
