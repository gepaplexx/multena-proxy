package utils

import (
	"database/sql"
	"github.com/go-sql-driver/mysql"
	"os"
)

var DB *sql.DB

func InitDB() {
	cfg := mysql.Config{
		User:   os.Getenv("DB_USER"),
		Passwd: os.Getenv("DB_PASSWORD"),
		Net:    "tcp",
		Addr:   os.Getenv("DB_HOST") + ":" + os.Getenv("DB_PORT"),
		DBName: os.Getenv("DB_NAME"),
	}
	// Get a database handle.
	var err error
	DB, err = sql.Open("mysql", cfg.FormatDSN())
	LogIfPanic("Error opening database", err)
	defer func(db *sql.DB) {
		LogIfPanic("Error closing result", db.Close())
	}(DB)
}
