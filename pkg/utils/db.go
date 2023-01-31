package utils

import "database/sql"

var DB *sql.DB

func InitDBConnection() {
	err := error(nil)
	DB, err = sql.Open("mysql", "user:password@tcp()")
	LogPanic("Error opening database", err)
	defer func(db *sql.DB) {
		err := db.Close()
		LogPanic("Error closing result", err)
	}(DB)

}
