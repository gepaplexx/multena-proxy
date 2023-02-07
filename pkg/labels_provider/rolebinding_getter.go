package labels_provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/gepaplexx/multena-proxy/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func GetLabelsFromRoleBindings(username string) []string {
	utils.Logger.Debug("Searching namespaces")
	rolebindings, err := utils.ClientSet.RbacV1().RoleBindings("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: "metadata.name=gp-dev",
	})
	utils.LogIfError("Error while using KubeAPI", err)
	var namespaces []string
	for _, rb := range rolebindings.Items {
		for _, user := range rb.Subjects {
			if strings.ToLower(fmt.Sprintf("%s", user.Name)) == username {
				namespaces = append(namespaces, rb.Namespace)
			}
		}
	}
	utils.Logger.Debug("Finished Searching namespaces")
	return namespaces
}
