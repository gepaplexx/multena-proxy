package labels_provider

import (
	"context"
	"github.com/gepaplexx/multena-proxy/pkg/utils"
	"go.uber.org/zap"
	auth "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"strings"
	"time"
)

type rbacCheck struct {
	namespace string
	username  string
	timestamp time.Time
	groups    []string
}

func worker(id int, work <-chan rbacCheck, results chan<- string) {
	for check := range work {
		utils.Logger.Debug("Worker", zap.Int("id", id), zap.String("namespace", check.namespace), zap.Time("time", time.Now()))
		results <- checkNamespaceRBAC(check.namespace, check.username, check.groups)
		utils.Logger.Debug("AHHHHHHHHHHH", zap.Int("id", id), zap.Time("time", time.Now()))
	}
}

func checkNamespaceRBAC(ns string, username string, groups []string) string {
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
	utils.Logger.Debug("SAR request took ms", zap.Any("time", elapsed.Milliseconds()))
	if sarResponse.Status.Allowed {
		return ns
	}
	return ""

}

func GetLabelsRBAC(username string, groups []string) []string {
	namespaces, err := utils.ClientSet.CoreV1().Namespaces().List(context.TODO(), metav1.ListOptions{})
	utils.LogIfError("Error while using KubeAPI", err)
	utils.Logger.Debug("namespaces", zap.Any("namespaces", namespaces.Items))

	filterdNamespaces := []string{}
	skipFilterForAdminGroup := false
	if utils.Contains(groups, os.Getenv("ADMIN_GROUP")) {
		skipFilterForAdminGroup = true
	}
	for _, ns := range namespaces.Items {
		if skipFilterForAdminGroup {
		} else {
			if strings.Contains(ns.Name, "openshift") || strings.Contains(ns.Name, "kube") || strings.Contains(ns.Name, "gp") || strings.Contains(ns.Name, "default") {
				continue
			}
		}
		filterdNamespaces = append(filterdNamespaces, ns.Name)
	}
	utils.Logger.Debug("filtered namespaces", zap.Any("namespaces", filterdNamespaces))

	const workers = 100
	work := make(chan rbacCheck, len(filterdNamespaces))
	results := make(chan string, len(filterdNamespaces))

	for w := 1; w <= workers; w++ {
		go worker(w, work, results)
	}

	for _, ns := range filterdNamespaces {
		work <- rbacCheck{
			namespace: ns,
			username:  username,
			groups:    groups,
			timestamp: time.Now(),
		}
	}

jump:

	if len(results) == len(filterdNamespaces) {
		utils.Logger.Debug("All workers are done")
	} else {
		utils.Logger.Debug("Not all workers are done")
		time.Sleep(1 * time.Second)
		goto jump
	}

	close(work)
	close(results)

	allowedNamespaces := []string{}
	for ns := range results {
		if ns != "" {
			allowedNamespaces = append(allowedNamespaces, ns)
		}
	}
	utils.Logger.Info("allowed namespaces", zap.Any("namespaces", allowedNamespaces))
	return allowedNamespaces

}
