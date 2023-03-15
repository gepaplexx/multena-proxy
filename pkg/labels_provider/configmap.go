package labels_provider

import "github.com/gepaplexx/multena-proxy/pkg/utils"

func GetLabelsCM(username string) []string {
	labels := utils.C.Users[username]
	return labels
}
