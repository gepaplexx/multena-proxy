package utils

import (
	"database/sql"
	"github.com/go-sql-driver/mysql"
	"os"
)

var DB *sql.DB

func InitDB() {
	if C.Db.Enabled {
		password, err := os.ReadFile(C.Db.PasswordPath)
		LogIfPanic("could not read db password", err)
		cfg := mysql.Config{
			User:                 C.Db.User,
			Passwd:               string(password),
			Net:                  "tcp",
			AllowNativePasswords: true,
			Addr:                 C.Db.Host + ":" + string(C.Db.Port),
			DBName:               C.Db.DbName,
		}
		// Get a database handle.
		DB, err = sql.Open("mysql", cfg.FormatDSN())
		LogIfPanic("Error opening database", err)
	}
}

func CloseDB() {
	if DB != nil {
		LogIfPanic("Error closing result", DB.Close())
	}
}
