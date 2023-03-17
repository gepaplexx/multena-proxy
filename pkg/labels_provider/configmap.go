package labels_provider

import (
	"github.com/gepaplexx/multena-proxy/pkg/utils"
	"strings"
)

func GetLabelsCM(username string, groups []string) []string {
	labels := utils.C.Users[username]
	for _, group := range groups {
		labels = append(labels, utils.C.Groups[strings.ToLower(group)]...)
	}
	return labels
}
