package common

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"reflect"
	"strconv"
	"strings"
	"time"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func DiffSuppressOnLeadingSlash(_, old, new string, _ *schema.ResourceData) bool {
	return EnsureLeadingSlash(old) == EnsureLeadingSlash(new)
}

var allLetters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
var lowerLetters = []rune("abcdefghijklmnopqrstuvwxyz")

func GenerateRandomAlphaNumericString(length int) string {
	s := make([]rune, length)

	for i := range s {
		s[i] = allLetters[rand.Intn(len(allLetters))]
	}

	return string(s)
}

func GenerateRandomLowercasedString(length int) string {
	s := make([]rune, length)

	for i := range s {
		s[i] = lowerLetters[rand.Intn(len(lowerLetters))]
	}

	return string(s)
}

func ExpandStringList(configured []interface{}) []string {
	vs := make([]string, 0, len(configured))
	for _, v := range configured {
		val, ok := v.(string)
		if ok && val != "" {
			vs = append(vs, val)
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
	case *[]string:
		a := ptr.(*[]string)
		if v, ok := val.(string); ok {
			*a = []string{v}
			return
		}
		if v, ok := val.([]string); ok {
			*a = v
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

func GetTargetName(itemTargetsAssoc []akeyless_api.ItemTargetAssociation) string {

	if len(itemTargetsAssoc) == 0 {
		return ""
	}
	targets := itemTargetsAssoc

	if len(targets) == 1 {
		if targets[0].TargetName == nil {
			return ""
		}
		return *targets[0].TargetName
	}
	names := make([]string, 0)
	for _, t := range targets {
		if t.TargetName != nil {
			names = append(names, *t.TargetName)
		}
	}
	return strings.Join(names, ",")
}

func GetTargetType(itemTargetsAssoc []akeyless_api.ItemTargetAssociation) string {

	if len(itemTargetsAssoc) == 0 {
		return ""
	}
	return itemTargetsAssoc[0].GetTargetType()
}

func GetRotatorUscSync(associatedItems []akeyless_api.ItemUSCSyncAssociation, uscName, remoteSecretName string) (namespace string, exists bool) {
	for _, assoc := range associatedItems {
		if assoc.ItemName == nil || *assoc.ItemName != uscName {
			continue
		}

		if assoc.Attributes == nil {
			return "", false
		}
		attr := *assoc.Attributes

		if attr.SecretName == nil || *attr.SecretName != remoteSecretName {
			return "", false
		}

		return attr.GetNamespace(), true
	}
	return "", false
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

func GetSraFromItem(d *schema.ResourceData, item *akeyless_api.Item) error {

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
		if len(s) == 1 && (s)[0] == "" {
			s = []string{}
		}
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

func Base64Decode(input string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(input)
	return string(b), err
}

func EnsureLeadingSlash(path string) string {
	if len(path) != 0 && !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
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

var gatewayURL = os.Getenv("AKEYLESS_GATEWAY")

func IsLocalEnv() bool {
	if gatewayURL == "http://localhost:8080/v2" || gatewayURL == "http://127.0.0.1:8080/v2" {
		return true
	}
	return false
}

func HandleError(msg string, resp *http.Response, err error) error {
	if err == nil {
		return nil
	}

	// err is informative
	var apiErr akeyless_api.GenericOpenAPIError
	if errors.As(err, &apiErr) {
		return fmt.Errorf("%s: %s", msg, string(apiErr.Body()))
	}

	// resp is informative
	if resp.Body != nil {
		if errorMsg, errRead := io.ReadAll(resp.Body); errRead == nil {
			return fmt.Errorf("%s: %s", msg, string(errorMsg))
		}
	}

	// nothing informative
	if resp.StatusCode == http.StatusNotFound {
		return fmt.Errorf("%s: not found: %w", msg, err)
	}
	return fmt.Errorf("%s: %w", msg, err)
}

func HandleReadError(d *schema.ResourceData, msg string, resp *http.Response, err error) error {
	if err == nil {
		return nil
	}

	// err is informative
	var apiErr akeyless_api.GenericOpenAPIError
	if errors.As(err, &apiErr) && resp != nil {
		if resp.StatusCode == http.StatusNotFound {
			// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
			d.SetId("")
		}
		return fmt.Errorf("%s: %s", msg, string(apiErr.Body()))
	}

	// resp is informative
	if resp != nil && resp.Body != nil {
		if errorMsg, errRead := io.ReadAll(resp.Body); errRead == nil {
			return fmt.Errorf("%s: %s", msg, string(errorMsg))
		}
	}

	// nothing informative
	if resp != nil && resp.StatusCode == http.StatusNotFound {
		// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
		d.SetId("")
		return fmt.Errorf("%s: not found: %w", msg, err)
	}
	return fmt.Errorf("%s: %w", msg, err)
}

func ValidateEventForwarderUpdateParams(d *schema.ResourceData) error {
	paramsMustNotUpdate := []string{"runner_type", "every"}
	return GetErrorOnUpdateParam(d, paramsMustNotUpdate)
}

func SetCommonEventForwarderVars(d *schema.ResourceData, rOut *akeyless_api.NotiForwarder) error {
	if rOut.Paths != nil {
		err := setEventSourceLocations(d, rOut.Paths)
		if err != nil {
			return err
		}
	}
	if rOut.EventTypes != nil {
		err := d.Set("event_types", rOut.EventTypes)
		if err != nil {
			return err
		}
	}
	if rOut.ProtectionKey != nil {
		if !strings.Contains(*rOut.ProtectionKey, "__account-def-secrets-key__") {
			err := d.Set("key", *rOut.ProtectionKey)
			if err != nil {
				return err
			}
		}
	}
	if rOut.RunnerType != nil {
		err := d.Set("runner_type", *rOut.RunnerType)
		if err != nil {
			return err
		}
	}
	if rOut.TimespanInSeconds != nil {
		err := d.Set("every", fmt.Sprintf("%d", *rOut.TimespanInSeconds/3600))
		if err != nil {
			return err
		}
	}
	if rOut.Comment != nil {
		err := d.Set("description", *rOut.Comment)
		if err != nil {
			return err
		}
	}
	return nil
}

func setEventSourceLocations(d *schema.ResourceData, paths []string) error {
	if len(paths) == 0 {
		return nil
	}
	items := make([]string, 0)
	authMethods := make([]string, 0)
	targets := make([]string, 0)
	gateways := make([]string, 0)

	for _, path := range paths {
		if strings.HasPrefix(path, "item:") {
			items = append(items, strings.TrimPrefix(path, "item:"))
		} else if strings.HasPrefix(path, "auth_method:") {
			authMethods = append(authMethods, strings.TrimPrefix(path, "auth_method:"))
		} else if strings.HasPrefix(path, "target:") {
			targets = append(targets, strings.TrimPrefix(path, "target:"))
		} else if strings.HasPrefix(path, "gateway:") {
			gateways = append(gateways, strings.TrimPrefix(path, "gateway:"))
		}
	}

	currentItemsSet := d.Get("items_event_source_locations").(*schema.Set)
	currentItems := ExpandStringList(currentItemsSet.List())
	if areListsDifferent(currentItems, items) {
		err := d.Set("items_event_source_locations", items)
		if err != nil {
			return err
		}
	}

	currentAMSet := d.Get("auth_methods_event_source_locations").(*schema.Set)
	currentAM := ExpandStringList(currentAMSet.List())
	if areListsDifferent(currentAM, authMethods) {
		err := d.Set("auth_methods_event_source_locations", authMethods)
		if err != nil {
			return err
		}
	}

	currentTargetsSet := d.Get("targets_event_source_locations").(*schema.Set)
	currentTargets := ExpandStringList(currentTargetsSet.List())
	if areListsDifferent(currentTargets, targets) {
		err := d.Set("targets_event_source_locations", targets)
		if err != nil {
			return err
		}
	}

	// we can't set gateways_event_source_locations as input is URL list but output is ClusterId list
	gatewaysLen := d.Get("gateways_event_source_locations").(*schema.Set).Len()
	if gatewaysLen > 0 && gatewaysLen != len(gateways) {
		return fmt.Errorf("gateway event source locations should be set. Expected %d, got %d", gatewaysLen, len(gateways))
	}

	return nil
}

func areListsDifferent(a, b []string) bool {
	if len(a) != len(b) {
		return true
	}
	mapA := make(map[string]struct{}, len(a))
	for _, item := range a {
		mapA[EnsureLeadingSlash(item)] = struct{}{}
	}
	for _, itemB := range b {
		item := EnsureLeadingSlash(itemB)
		if _, exists := mapA[item]; !exists {
			return true
		}
		delete(mapA, item)
	}
	if len(mapA) > 0 {
		return true
	}
	return false
}
