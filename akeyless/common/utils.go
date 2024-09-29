package common

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const accountDefKey = "account-def-secrets-key"

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

	switch ptr.(type) {
	case *string:
		if v, ok := val.(string); ok {
			a := ptr.(*string)
			*a = v
			return
		}
	case **string:
		if v, ok := val.(string); ok {
			a := ptr.(**string)
			*a = akeyless_api.PtrString(v)
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
			*a = akeyless_api.PtrBool(v)
			return
		}
	case *bool:
		if v, ok := val.(bool); ok {
			a := ptr.(*bool)
			*a = v
			return
		}
	case **int64:
		if v, ok := val.(int); ok {
			a := ptr.(**int64)
			*a = akeyless_api.PtrInt64(int64(v))
			return
		}
	case **int32:
		if v, ok := val.(int); ok {
			a := ptr.(**int32)
			*a = akeyless_api.PtrInt32(int32(v))
			return
		}
	case **int:
		if v, ok := val.(int); ok {
			a := ptr.(**int)
			*a = akeyless_api.PtrInt(v)
			return
		}
	case *int64:
		if v, ok := val.(int); ok {
			a := ptr.(*int64)
			*a = int64(v)
			return
		}
	case *int32:
		if v, ok := val.(int); ok {
			a := ptr.(*int32)
			*a = int32(v)
			return
		}
	case *int:
		if v, ok := val.(int); ok {
			a := ptr.(*int)
			*a = v
			return
		}
	case **float32:
		if v, ok := val.(float32); ok {
			a := ptr.(**float32)
			*a = akeyless_api.PtrFloat32(v)
			return
		}
	case **float64:
		if v, ok := val.(float64); ok {
			a := ptr.(**float64)
			*a = akeyless_api.PtrFloat64(v)
			return
		}
	case **time.Time:
		if v, ok := val.(time.Time); ok {
			a := ptr.(**time.Time)
			*a = akeyless_api.PtrTime(v)
			return
		}
	case *float32:
		if v, ok := val.(float32); ok {
			a := ptr.(*float32)
			*a = v
			return
		}
	case *float64:
		if v, ok := val.(float64); ok {
			a := ptr.(*float64)
			*a = v
			return
		}
	case *time.Time:
		if v, ok := val.(time.Time); ok {
			a := ptr.(*time.Time)
			*a = v
			return
		}
	case **map[string]string:
		if v, ok := val.(map[string]interface{}); ok {
			mapString := make(map[string]string)
			for key, value := range v {
				strKey := fmt.Sprintf("%v", key)
				strValue := fmt.Sprintf("%v", value)
				mapString[strKey] = strValue
			}
			a := ptr.(**map[string]string)
			*a = &mapString
			return
		}
	default:
		panic("invalid type")
		//*ptr = val
	}
}

func GetTargetName(itemTargetsAssoc *[]akeyless_api.ItemTargetAssociation) string {
	if itemTargetsAssoc == nil {
		return ""
	}
	if len(*itemTargetsAssoc) == 0 {
		return ""
	}
	targets := *itemTargetsAssoc
	if len(targets) == 1 {
		if targets[0].TargetName == nil {
			return ""
		}
		return *targets[0].TargetName
	}
	names := make([]string, 0)
	for _, t := range targets {
		if t.TargetName != nil {
			names = append(names)
		}
	}
	return strings.Join(names, ",")
}

func GetTagsForUpdate(d *schema.ResourceData, name, token string, newTags []string,
	client akeyless_api.V2ApiService) ([]string, []string, error) {
	ctx := context.Background()

	item := akeyless_api.GetTags{
		Name:  name,
		Token: &token,
	}

	oldTags, _, err := client.GetTags(ctx).Body(item).Execute()
	if err != nil {
		return nil, nil, err
	}

	if len(oldTags) == 0 {
		return newTags, nil, nil
	}
	add := difference(newTags, oldTags)
	remove := difference(oldTags, newTags)
	return add, remove, nil
}

// difference returns the elements in `a` that aren't in `b`.
func difference(a, b []string) []string {
	mb := make(map[string]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []string
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

func GetSraWithDescribeItem(d *schema.ResourceData, path, token string, client akeyless_api.V2ApiService) error {

	ctx := context.Background()

	item := akeyless_api.DescribeItem{
		Name:         path,
		ShowVersions: akeyless_api.PtrBool(false),
		Token:        &token,
	}

	itemOut, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return err
	}

	return GetSraFromItem(d, itemOut)
}

func GetSraFromItem(d *schema.ResourceData, item akeyless_api.Item) error {

	if item.GetItemGeneralInfo().SecureRemoteAccessDetails == nil {
		return nil
	}

	itemType := *item.ItemType
	sra := item.GetItemGeneralInfo().SecureRemoteAccessDetails

	return GetSra(d, sra, itemType)
}

func GetSra(d *schema.ResourceData, sra *akeyless_api.SecureRemoteAccess, itemType string) error {
	var err error
	if sra == nil {
		return nil
	}

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
		err = d.Set("secure_access_bastion_api", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetBastionSshOk(); ok {
		err = d.Set("secure_access_bastion_ssh", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetSshUserOk(); ok {
		if itemType == "STATIC_SECRET" {
			err = d.Set("secure_access_ssh_user", s)
			if err != nil {
				return err
			}
		} else { //cert-issuer
			err = d.Set("secure_access_ssh_creds_user", s)
			if err != nil {
				return err
			}
		}
	}

	// if s, ok := sra.GetIsCliOk(); ok && *s {
	// 	err = d.Set("secure_access_ssh_creds", s)
	// 	if err != nil {
	// 		return err
	// 	}
	// }

	if s, ok := sra.GetUseInternalBastionOk(); ok && *s {
		err = d.Set("secure_access_use_internal_bastion", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetNativeOk(); ok && *s {
		err = d.Set("secure_access_aws_native_cli", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetHostOk(); ok {
		err = d.Set("secure_access_host", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetIsWebOk(); ok && *s {
		err = d.Set("secure_access_web", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetWebProxyOk(); ok && *s {
		err = d.Set("secure_access_web_proxy", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetIsolatedOk(); ok && *s {
		err = d.Set("secure_access_web_browsing", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetDomainOk(); ok {
		err = d.Set("secure_access_rdp_domain", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetRdpUserOk(); ok {
		err = d.Set("secure_access_rdp_user", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetAllowProvidingExternalUsernameOk(); ok && *s {
		err = d.Set("secure_access_allow_external_user", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetSchemaOk(); ok {
		err = d.Set("secure_access_db_schema", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetDbNameOk(); ok {
		err = d.Set("secure_access_db_name", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetAccountIdOk(); ok {
		err = d.Set("secure_access_aws_account_id", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetRegionOk(); ok {
		err = d.Set("secure_access_aws_region", s)
		if err != nil {
			return err
		}
	}
	if s, ok := sra.GetRegionOk(); ok {
		err = d.Set("secure_access_aws_region", s)
		if err != nil {
			return err
		}
	}

	if s, ok := sra.GetEndpointOk(); ok {
		err = d.Set("secure_access_cluster_endpoint", s)
		if err != nil {
			return err
		}
	}
	if s, ok := sra.GetDashboardUrlOk(); ok {
		err = d.Set("secure_access_dashboard_url", s)
		if err != nil {
			return err
		}
	}
	if s, ok := sra.GetAllowPortForwardingOk(); ok && *s {
		err = d.Set("secure_access_allow_port_forwading", s)
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

func GetErrorOnUpdateParam(d *schema.ResourceData, paramNames []string) error {
	changed := []string{}

	for _, paramName := range paramNames {
		if d.HasChange(paramName) {
			// need to explicit rollback param due to unresolved bug in terraform:
			// https://github.com/hashicorp/terraform-provider-helm/issues/472
			old, _ := d.GetChange(paramName)
			d.Set(paramName, old)

			changed = append(changed, paramName)
		}
	}

	if len(changed) > 0 {
		changedParams := "\"" + strings.Join(changed, "\", \"") + "\""
		return fmt.Errorf("update of %s is not allowed", changedParams)
	}
	return nil
}

func ConvertNanoSecondsIntoDurationString(nano int64) string {
	nanoUnix := time.Unix(0, nano)
	duration := nanoUnix.Sub(time.Unix(0, 0))
	return duration.String()
}

func ReadAndEncodeFile(fileName string) (string, error) {
	bytes, err := os.ReadFile(fileName)
	if err != nil {
		return "", err
	}
	data := base64.StdEncoding.EncodeToString(bytes)
	if len(data) == 0 {
		return "", errors.New("")
	}
	return data, nil
}

func Base64Encode(input string) string {
	return base64.StdEncoding.EncodeToString([]byte(input))
}

func SetDataByPrefixSlash(d *schema.ResourceData, key, returnedValue, existValue string) error {
	if "/"+returnedValue == existValue {
		return d.Set(key, existValue)
	}
	return d.Set(key, returnedValue)
}

// SecondsToTimeString converts a total number of seconds to a formatted string like "1d2h3m4s".
func SecondsToTimeString(totalSeconds int) string {
	const secondsInAMinute = 60
	const secondsInAnHour = secondsInAMinute * 60
	const secondsInADay = secondsInAnHour * 24

	days := totalSeconds / secondsInADay
	remainSeconds := totalSeconds % secondsInADay

	hours := remainSeconds / secondsInAnHour
	remainSeconds %= secondsInAnHour

	minutes := remainSeconds / secondsInAMinute
	remainSeconds %= secondsInAMinute

	seconds := remainSeconds

	var result strings.Builder
	if days > 0 {
		result.WriteString(fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		result.WriteString(fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		result.WriteString(fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 || result.Len() == 0 {
		result.WriteString(fmt.Sprintf("%ds", seconds))
	}

	return result.String()
}

func ExtractLogForwardingFormat(isJson bool) string {
	if isJson {
		return "json"
	}
	return "text"
}

func ReadExpirationEventInParam(expirationEvents []akeyless_api.CertificateExpirationEvent) []string {
	var expirationEventsList []string
	for _, e := range expirationEvents {
		seconds := e.GetSecondsBefore()
		days := seconds / 60 / 60 / 24
		expirationEventsList = append(expirationEventsList, strconv.FormatInt(days, 10))
	}
	return expirationEventsList
}

func ReadRotationEventInParam(expirationEvents []akeyless_api.NextAutoRotationEvent) []string {
	var expirationEventsList []string
	for _, e := range expirationEvents {
		seconds := e.GetSecondsBefore()
		days := seconds / 60 / 60 / 24
		expirationEventsList = append(expirationEventsList, strconv.FormatInt(days, 10))
	}
	return expirationEventsList
}

func UpdateRotationSettings(d *schema.ResourceData, name string, token string, client akeyless_api.V2ApiService) error {
	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	if d.HasChanges("auto_rotate", "rotation_interval", "rotation_event_in") {
		autoRotate := d.Get("auto_rotate").(string)
		autoRotateBool, err := strconv.ParseBool(autoRotate)
		if err != nil {
			return fmt.Errorf("failed to parse bool of auto rotate %s: %w", autoRotate, err)
		}
		rotationInterval := d.Get("rotation_interval").(string)
		rotationIntervalInt, err := strconv.Atoi(rotationInterval)
		if err != nil {
			return fmt.Errorf("failed to parse int of rotation interval %s: %w", rotationInterval, err)
		}
		rotationEventInSet := d.Get("rotation_event_in").(*schema.Set)
		rotationEventInList := ExpandStringList(rotationEventInSet.List())

		rotationSettingsBody := akeyless_api.UpdateRotationSettings{
			Name:  name,
			Token: &token,
		}
		GetAkeylessPtr(&rotationSettingsBody.AutoRotate, autoRotateBool)
		GetAkeylessPtr(&rotationSettingsBody.RotationInterval, rotationIntervalInt)
		GetAkeylessPtr(&rotationSettingsBody.RotationEventIn, rotationEventInList)

		_, _, err = client.UpdateRotationSettings(ctx).Body(rotationSettingsBody).Execute()
		if err != nil {
			if errors.As(err, &apiErr) {
				return fmt.Errorf("failed to update rotation settings: %v", string(apiErr.Body()))
			}
			return fmt.Errorf("failed to update rotation settings: %w", err)
		}
	}
	return nil
}
