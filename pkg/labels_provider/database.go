package labels_provider

import (
	"database/sql"
	"github.com/gepaplexx/multena-proxy/pkg/utils"
)

func GetLabelsFromDB(email string) []string {
	db := utils.DB
	res, err := db.Query("SELECT * FROM user WHERE email = ?", email)
	defer func(res *sql.Rows) {
		err := res.Close()
		utils.LogIfPanic("Error closing result", err)
	}(res)
	utils.LogIfPanic("Error querying database", err)
	labels := []string{}
	if res.Next() {
		err := res.Scan(&labels)
		utils.LogIfPanic("Error scanning result", err)
	} else {
		utils.LogIfError("Error no rows", err)
	}
	return labels

}
