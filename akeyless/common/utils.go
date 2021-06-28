package common

import "github.com/hashicorp/terraform-plugin-sdk/v2/diag"

func ExpandStringList(configured []interface{}) []string {
	vs := make([]string, 0, len(configured))
	for _, v := range configured {
		val, ok := v.(string)
		if ok && val != "" {
			vs = append(vs, v.(string))
		}
	}
	return vs
}

func ErrorDiagnostics(message string) diag.Diagnostic {
	return diag.Diagnostic{
		Severity: diag.Error,
		Summary:  message,
	}
}

func WarningDiagnostics(message string) diag.Diagnostic {
	return diag.Diagnostic{
		Severity: diag.Warning,
		Summary:  message,
	}
}
