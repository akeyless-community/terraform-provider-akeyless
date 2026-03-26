package akeyless

import (
	"fmt"
	"strings"
)

func getServiceAccountType(k8sDynamicMode bool) string {
	if k8sDynamicMode {
		return "dynamic"
	}
	return "fixed"
}

func getServiceAccountPredefinedRoleType(roleType string) (string, error) {
	normalized := strings.TrimSpace(roleType)
	if normalized == "" {
		return "", nil
	}

	switch strings.ToLower(normalized) {
	case "role", "k8s_role":
		return "Role", nil
	case "clusterrole", "cluster_role", "k8s_cluster_role":
		return "ClusterRole", nil
	default:
		return "", fmt.Errorf("unsupported k8s role type: %s", roleType)
	}
}

func removeIgnoredEntriesFromList(permissionsMap map[string]string, tokenPermissionsList []string) []string {
	if len(tokenPermissionsList) == 0 {
		return []string{}
	}

	result := make([]string, 0, len(tokenPermissionsList))
	seen := make(map[string]struct{}, len(tokenPermissionsList))
	for _, entry := range tokenPermissionsList {
		key, value := splitPermissionEntry(entry)
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}

		if mappedValue, ok := permissionsMap[key]; ok {
			result = append(result, fmt.Sprintf("%s=%s", key, mappedValue))
		} else if value != "" {
			result = append(result, entry)
		}

		seen[key] = struct{}{}
	}

	return result
}

func splitPermissionEntry(entry string) (string, string) {
	parts := strings.SplitN(entry, "=", 2)
	if len(parts) < 2 {
		parts = strings.SplitN(entry, ":", 2)
	}

	key := strings.TrimSpace(parts[0])
	value := ""
	if len(parts) == 2 {
		value = strings.TrimSpace(parts[1])
	}
	return key, value
}
