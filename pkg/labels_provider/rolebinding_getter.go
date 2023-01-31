package labels_provider

import (
	"context"
	"fmt"
	"github.com/gepaplexx/namespace-proxy/pkg/utils"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientset "k8s.io/client-go/kubernetes"
	"strings"
)

func GetLabelsFromRoleBindings(username string) []string {
	utils.Logger.Debug("Searching namespaces")
	rolebindings, err := clientset.RbacV1().RoleBindings("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: "metadata.name=gp-dev",
	})
	utils.LogError("Error while using KubeAPI", err)
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
