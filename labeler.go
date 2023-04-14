package main

import (
	"database/sql"
	"errors"
	"fmt"
	"go.uber.org/zap"
	"golang.org/x/net/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"os"
	"regexp"
	"strings"
)

func GetLabelsCM(username string, groups []string) []string {
	labels := C.Users[username]
	for _, group := range groups {
		labels = append(labels, C.Groups[strings.ToLower(group)]...)
	}
	return labels
}

func GetLabelsFromDB(email string) []string {
	db := DB
	stmt := os.Getenv("LABEL_DB_QUERY")
	n := strings.Count(stmt, "?")

	var params []any
	for i := 0; i < n; i++ {
		params = append(params, email)
	}

	res, err := db.Query(stmt, params...)
	defer func(res *sql.Rows) {
		err := res.Close()
		if err != nil {
			Logger.Panic("Error closing DB result", zap.Error(err))
		}
	}(res)
	if err != nil {
		Logger.Panic("Error while querying database", zap.Error(err))
	}
	var labels []string
	for res.Next() {
		var label string
		err = res.Scan(&label)
		labels = append(labels, label)
		if err != nil {
			Logger.Panic("Error scanning DB result", zap.Error(err))
		}
	}
	return labels
}

func GetLabelsFromProject(username string) []string {
	Logger.Debug("Searching namespaces")
	rolebindings, err := ClientSet.RbacV1().RoleBindings("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: "metadata.name=gp-dev",
	})
	if err != nil {
		Logger.Error("Error while using KubeAPI", zap.Error(err))
	}
	var namespaces []string
	for _, rb := range rolebindings.Items {
		for _, user := range rb.Subjects {
			if strings.ToLower(fmt.Sprintf("%s", user.Name)) == username {
				namespaces = append(namespaces, rb.Namespace)
			}
		}
	}
	Logger.Debug("Finished Searching namespaces")
	return namespaces
}

func enforceNamespaces(query string, namespaces []string) (string, error) {
	if len(namespaces) == 0 {
		return "", errors.New("namespaces slice cannot be empty")
	}

	namespaceRegex := regexp.MustCompile(`kubernetes_namespace_name\s*=\s*"?([^"{}\s,|]+)"?`)
	namespaceListRegex := regexp.MustCompile(`kubernetes_namespace_name\s*=\s*~\s*"?([^"{}\s,]+)"?`)
	selectorRegex := regexp.MustCompile(`\{([^\{\}]+)\}`)
	goTemplateRegex := regexp.MustCompile(`{{[^}]*}}`)

	enforcedNamespaceList := strings.Join(namespaces, "|")

	// Check if kubernetes_namespace_name is already in the query and if it contains disallowed namespaces
	if namespaceRegex.MatchString(query) || namespaceListRegex.MatchString(query) {
		namespacesFound := make(map[string]bool)
		for _, match := range namespaceRegex.FindAllStringSubmatch(query, -1) {
			namespacesFound[match[1]] = true
		}
		for _, match := range namespaceListRegex.FindAllStringSubmatch(query, -1) {
			for _, ns := range strings.Split(match[1], "|") {
				namespacesFound[ns] = true
			}
		}
		delete(namespacesFound, "~")
		for ns := range namespacesFound {
			if !contains(namespaces, ns) {
				return "", errors.New("query contains disallowed namespaces")
			}
		}

		return query, nil // Return the original query if it contains only allowed namespaces
	}

	// Split query into parts
	parts := goTemplateRegex.Split(query, -1)
	placeholders := goTemplateRegex.FindAllString(query, -1)

	// Add kubernetes_namespace_name to the query if it's not present
	for i, part := range parts {
		if selectorRegex.MatchString(part) && !strings.Contains(part, "kubernetes_namespace_name") {
			replacer := func(match string) string {
				if len(namespaces) == 1 {
					return fmt.Sprintf("{%s, kubernetes_namespace_name=%q}", match[1:len(match)-1], namespaces[0])
				}
				return fmt.Sprintf("{%s, kubernetes_namespace_name=~%q}", match[1:len(match)-1], enforcedNamespaceList)
			}
			parts[i] = selectorRegex.ReplaceAllStringFunc(part, replacer)
		}
	}

	// Rejoin the parts and placeholders
	var result strings.Builder
	for i, part := range parts {
		result.WriteString(part)
		if i < len(placeholders) {
			result.WriteString(placeholders[i])
		}
	}

	return result.String(), nil
}

func contains(slice []string, item string) bool {
	for _, i := range slice {
		if i == item {
			return true
		}
	}
	return false
}
