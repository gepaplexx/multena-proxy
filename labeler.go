package main

import (
	"database/sql"
	"go.uber.org/zap"
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
