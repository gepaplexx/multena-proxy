package labels_provider

import (
	"context"
	"github.com/gepaplexx/multena-proxy/pkg/utils"
	"go.uber.org/zap"
	auth "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"strings"
	"time"
)

func GetLabelsRBAC(username string, groups []string) []string {
	namespaces, err := utils.ClientSet.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	utils.LogIfError("Error while using KubeAPI", err)
	utils.Logger.Debug("namespaces", zap.Any("namespaces", namespaces.Items))
	filterdNamespaces := []string{}
	for _, ns := range namespaces.Items {
		if strings.Contains(ns.Name, "openshift") || strings.Contains(ns.Name, "kube") || strings.Contains(ns.Name, "gp") || strings.Contains(ns.Name, "default") {
			continue
		} else {
			filterdNamespaces = append(filterdNamespaces, ns.Name)
		}
	}
	utils.Logger.Debug("filtered namespaces", zap.Any("namespaces", filterdNamespaces))

	allowedNamespaces := []string{}

	for _, ns := range filterdNamespaces {
		utils.Logger.Debug("Checking namespace", zap.String("namespace", ns))
		sar := auth.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{
				Kind:       "SubjectAccessReview",
				APIVersion: "authorization.k8s.io/v1",
			},
			Spec: auth.SubjectAccessReviewSpec{
				ResourceAttributes: &auth.ResourceAttributes{
					Namespace: ns,
					Verb:      "get",
					Version:   "*",
					Resource:  "*",
				},
				User:   username,
				Groups: groups,
			},
		}
		start := time.Now()
		sarResponse, err := utils.ClientSet.AuthorizationV1().SubjectAccessReviews().Create(context.Background(), &sar, metav1.CreateOptions{})
		elapsed := time.Since(start)
		utils.LogIfError("Error while using KubeAPI", err)
		utils.Logger.Debug("SAR request took", zap.Any("time", elapsed))
		utils.Logger.Debug("SAR response", zap.Any("response", sarResponse))
		if sarResponse.Status.Allowed {
			allowedNamespaces = append(allowedNamespaces, ns)
		}
	}
	utils.Logger.Debug("allowed namespaces", zap.Any("namespaces", allowedNamespaces))
	return allowedNamespaces

}
