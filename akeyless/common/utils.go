package common

import (
	"context"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

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

func GetAkeylessPtr(ptr interface{}, val interface{}) {

	//fmt.Printf("t1: %T \n", ptr)

	switch ptr.(type) {
	case **string:
		if v, ok := val.(string); ok {
			a := ptr.(**string)
			*a = akeyless.PtrString(v)
			return
		}
	case **[]string:
		a := ptr.(**[]string)
		if v, ok := val.(string); ok {
			*a = &[]string{v}
			return
		}
		if v, ok := val.([]string); ok {
			*a = &v
			return
		}
	case **bool:
		if v, ok := val.(bool); ok {
			a := ptr.(**bool)
			*a = akeyless.PtrBool(v)
			return
		}
	case **int64:
		if v, ok := val.(int64); ok {
			a := ptr.(**int64)
			*a = akeyless.PtrInt64(v)
			return
		}
	case **int32:
		if v, ok := val.(int32); ok {
			a := ptr.(**int32)
			*a = akeyless.PtrInt32(v)
			return
		}
	case **int:
		if v, ok := val.(int); ok {
			a := ptr.(**int)
			*a = akeyless.PtrInt(v)
			return
		}
	case **float32:
		if v, ok := val.(float32); ok {
			a := ptr.(**float32)
			*a = akeyless.PtrFloat32(v)
			return
		}
	case **float64:
		if v, ok := val.(float64); ok {
			a := ptr.(**float64)
			*a = akeyless.PtrFloat64(v)
			return
		}
	case **time.Time:
		if v, ok := val.(time.Time); ok {
			a := ptr.(**time.Time)
			*a = akeyless.PtrTime(v)
			return
		}
	default:
		//*ptr = val
	}
}

func GetSra(d *schema.ResourceData, path, token string, client akeyless.V2ApiService) error {

	ctx := context.Background()

	item := akeyless.DescribeItem{
		Name:         path,
		ShowVersions: akeyless.PtrBool(false),
		Token:        &token,
	}

	itemOut, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return err
	}

	if itemOut.GetItemGeneralInfo().SecureRemoteAccessDetails == nil {
		return nil
	}
	sra := itemOut.GetItemGeneralInfo().SecureRemoteAccessDetails

	if _, ok := sra.GetEnableOk(); ok {
		err = d.Set("secure_access_enable", strconv.FormatBool(sra.GetEnable()))
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetUrlOk(); ok {
		err = d.Set("secure_access_url", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetBastionIssuerOk(); ok {
		err = d.Set("secure_access_bastion_issuer", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetBastionApiOk(); ok {
		err = d.Set("secure-access-bastion-api", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetBastionSshOk(); ok {
		err = d.Set("secure-access-bastion-ssh", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetSshUserOk(); ok {
		err = d.Set("secure-access-ssh-creds-user", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetIsCliOk(); ok && *s {
		err = d.Set("secure-access-ssh-creds", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetUseInternalBastionOk(); ok && *s {
		err = d.Set("secure-access-use-internal-bastion", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetHostOk(); ok {
		err = d.Set("secure-access-host", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetIsWebOk(); ok && *s {
		err = d.Set("secure-access-web-browsing", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetDomainOk(); ok {
		err = d.Set("secure-access-rdp-domain", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetRdpUserOk(); ok {
		err = d.Set("secure-access-rdp-user", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetAllowProvidingExternalUsernameOk(); ok && *s {
		err = d.Set("secure-access-allow-external-user", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetSchemaOk(); ok {
		err = d.Set("secure-access-db-schema", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetDbNameOk(); ok {
		err = d.Set("secure-access-db-name", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetAccountIdOk(); ok {
		err = d.Set("secure-access-aws-account-id", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetRegionOk(); ok {
		err = d.Set("secure-access-aws-region", s)
		if err != nil {
			return err
		}
	}
	if s, ok := sra.GetRegionOk(); ok {
		err = d.Set("secure-access-aws-region", s)
		if err != nil {
			return err
		}
	}
	if s, ok := sra.GetNativeOk(); ok && *s {
		err = d.Set("secure-access-aws-native-cli", s)
		if err != nil {
			return err
		}
	}
	if s, ok := sra.GetEndpointOk(); ok {
		err = d.Set("secure-access-cluster-endpoint", s)
		if err != nil {
			return err
		}
	}
	if s, ok := sra.GetDashboardUrlOk(); ok {
		err = d.Set("secure-access-dashboard-url", s)
		if err != nil {
			return err
		}
	}
	if s, ok := sra.GetAllowPortForwardingOk(); ok && *s {
		err = d.Set("secure-access-allow-port-forwading", s)
		if err != nil {
			return err
		}
	}

	return nil
}

func GetFieldjsonTagName(tag string, s interface{}) (fieldname string) {
	rt := reflect.TypeOf(s)
	if rt.Kind() != reflect.Struct {
		//panic("bad type")
		return ""
	}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		v := strings.Split(f.Tag.Get("json"), ",")[0] // use split to ignore tag "options" like omitempty, etc.
		if v == tag {
			return f.Name
		}
	}
	return ""
}
