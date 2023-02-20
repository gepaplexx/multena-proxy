package labels_provider

import (
	"database/sql"
	"github.com/gepaplexx/multena-proxy/pkg/utils"
	"os"
	"strings"
)

//const stmt = "SELECT sla.service_instance AS bla " +
//	"FROM person p " +
//	"JOIN service_level_agreement_coverage_person slap ON slap.person = p.id " +
//	"JOIN service_level_agreement sla ON slap.serviceLevelAgreement = sla.id " +
//	"WHERE p.primary_email = ? " +
//	"AND p.disabled = 0 " +
//	"UNION " +
//	"SELECT sla.service_instance AS bla " +
//	"FROM person p " +
//	"JOIN service_level_agreement_coverage_organization slao ON slao.organization = p.organization " +
//	"JOIN service_level_agreement sla ON slao.serviceLevelAgreement = sla.id " +
//	"WHERE p.primary_email = ? " +
//	"AND p.disabled = 0"

func GetLabelsFromDB(email string) []string {
	db := utils.DB
	stmt := os.Getenv("LABEL_DB_QUERY")
	n := strings.Count(stmt, "?")

	var params []any
	for i := 0; i < n; i++ {
		params = append(params, email)
	}

	res, err := db.Query(stmt, params...)
	defer func(res *sql.Rows) {
		err := res.Close()
		utils.LogIfPanic("Error closing result", err)
	}(res)
	utils.LogIfPanic("Error querying database", err)
	var labels []string
	for res.Next() {
		var label string
		err = res.Scan(&label)
		labels = append(labels, label)
		utils.LogIfPanic("Error scanning result", err)
	}
	return labels
}
