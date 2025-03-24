// generated file
package akeyless

import (
	"context"
	"fmt"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceUscSecret() *schema.Resource {
	return &schema.Resource{
		Description: "Universal Secrets Connector secret resource",
		Create:      resourceUscSecretCreate,
		Read:        resourceUscSecretRead,
		Update:      resourceUscSecretUpdate,
		Delete:      resourceUscSecretDelete,
		Importer: &schema.ResourceImporter{
			State: resourceUscSecretImport,
		},
		Schema: map[string]*schema.Schema{
			"usc_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name of the Universal Secrets Connector item",
			},
			"secret_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Name for the new universal secrets",
			},
			"version_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Version ID of the secret (if not specified, will retrieve the last version)",
			},
			"value": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Value of the universal secrets item, either text or base64 encoded binary",
			},
			"binary_value": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Use this option if the universal secrets value is a base64 encoded binary. (relevant for aws/azure/gcp/k8s targets)",
			},
			"namespace": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The namespace (relevant for Hashi vault target)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the universal secret (relevant for aws/hashi target)",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Tags for the universal secrets",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secret_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "The ID of the universal secrets item",
			},
		},
	}
}

func resourceUscSecretCreate(d *schema.ResourceData, m any) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	uscName := d.Get("usc_name").(string)
	secretName := d.Get("secret_name").(string)
	value := d.Get("value").(string)
	binaryValue := d.Get("binary_value").(bool)
	namespace := d.Get("namespace").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless_api.UscCreate{
		UscName:    uscName,
		SecretName: secretName,
		Value:      value,
		Token:      &token,
	}
	common.GetAkeylessPtr(&body.BinaryValue, binaryValue)
	common.GetAkeylessPtr(&body.Namespace, namespace)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tags, tags)

	out, resp, err := client.UscCreate(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create usc secret", resp, err)
	}

	err = d.Set("secret_id", out.GetSecretId())
	if err != nil {
		return err
	}

	d.SetId(buildUscSecretId(uscName, secretName))

	return nil
}

func resourceUscSecretRead(d *schema.ResourceData, m any) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	uscName, secretName, err := extractUscNameAndSecretNameFromId(d.Id())
	if err != nil {
		return err
	}

	targetType, err := getItemTargetType(d, m)
	if err != nil {
		return err
	}

	secretId := getSecretIdByTargetType(d, targetType)

	versionId := d.Get("version_id").(string)
	namespace := d.Get("namespace").(string)

	body := akeyless_api.UscGet{
		UscName:  uscName,
		SecretId: secretId,
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.VersionId, versionId)
	common.GetAkeylessPtr(&body.Namespace, namespace)

	rOut, resp, err := client.UscGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get usc secret", resp, err)
	}

	if rOut.BinaryValue != nil {
		err := d.Set("binary_value", *rOut.BinaryValue)
		if err != nil {
			return err
		}
	}
	if rOut.Metadata != nil && d.Get("description").(string) != "" {
		err := d.Set("description", fmt.Sprintf("%v", rOut.Metadata))
		if err != nil {
			return err
		}
	}
	if rOut.Value != nil {
		value := *rOut.Value

		// value should be decoded, unless it provided as binary (encoded).
		// hashi vault target always expects encoded data.
		if !rOut.GetBinaryValue() && targetType != common.TargetTypeVault {
			decoded, err := common.Base64Decode(*rOut.Value)
			if err != nil {
				return err
			}
			value = decoded
		}

		err := d.Set("value", value)
		if err != nil {
			return err
		}
	}

	d.SetId(buildUscSecretId(uscName, secretName))

	return nil
}

func resourceUscSecretUpdate(d *schema.ResourceData, m any) error {

	err := validateUscSecretUpdateParams(d)
	if err != nil {
		return fmt.Errorf("can't update: %v", err)
	}

	secretId, err := getSecretId(d, m)
	if err != nil {
		return err
	}

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	uscName := d.Get("usc_name").(string)
	secretName := d.Get("secret_name").(string)
	value := d.Get("value").(string)
	binaryValue := d.Get("binary_value").(bool)
	namespace := d.Get("namespace").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless_api.UscUpdate{
		UscName:  uscName,
		SecretId: secretId,
		Value:    value,
		Token:    &token,
	}
	common.GetAkeylessPtr(&body.BinaryValue, binaryValue)
	common.GetAkeylessPtr(&body.Namespace, namespace)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tags, tags)

	_, resp, err := client.UscUpdate(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update usc secret", resp, err)
	}

	d.SetId(buildUscSecretId(uscName, secretName))

	return nil
}

func resourceUscSecretDelete(d *schema.ResourceData, m any) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	uscName, _, err := extractUscNameAndSecretNameFromId(d.Id())
	if err != nil {
		return err
	}

	secretId, err := getSecretId(d, m)
	if err != nil {
		return err
	}

	deleteItem := akeyless_api.UscDelete{
		Token:    &token,
		UscName:  uscName,
		SecretId: secretId,
	}

	ctx := context.Background()
	_, _, err = client.UscDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceUscSecretImport(d *schema.ResourceData, m any) ([]*schema.ResourceData, error) {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	uscName, secretName, err := extractUscNameAndSecretNameFromId(d.Id())
	if err != nil {
		return nil, err
	}

	item := akeyless_api.UscGet{
		UscName:  uscName,
		SecretId: secretName,
		Token:    &token,
	}

	ctx := context.Background()
	_, _, err = client.UscGet(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	d.SetId(buildUscSecretId(uscName, secretName))

	return []*schema.ResourceData{d}, nil
}

func getSecretId(d *schema.ResourceData, m any) (string, error) {

	targetType, err := getItemTargetType(d, m)
	if err != nil {
		return "", err
	}

	secretId := getSecretIdByTargetType(d, targetType)
	return secretId, nil
}

func getItemTargetType(d *schema.ResourceData, m any) (string, error) {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	uscName, _, err := extractUscNameAndSecretNameFromId(d.Id())
	if err != nil {
		return "", err
	}

	describeItemBody := akeyless_api.DescribeItem{
		Name:  uscName,
		Token: &token,
	}
	itemOut, resp, err := client.DescribeItem(ctx).Body(describeItemBody).Execute()
	if err != nil {
		return "", common.HandleReadError(d, "can't get usc details", resp, err)
	}

	targetType := common.GetTargetType(itemOut.ItemTargetsAssoc)
	if targetType == "" {
		return "", fmt.Errorf("usc %s has no associated targets", uscName)
	}

	return targetType, nil
}

const uscDelimiter string = "__"

func buildUscSecretId(uscName, secretName string) string {
	return fmt.Sprintf("%s%s%s", uscName, uscDelimiter, secretName)
}

func extractUscNameAndSecretNameFromId(id string) (string, string, error) {
	fields := strings.Split(id, uscDelimiter)
	if len(fields) != 2 {
		return "", "", fmt.Errorf("invalid id format: %s. expected format 'uscName__secretName'", id)
	}
	return fields[0], fields[1], nil
}

func getSecretIdByTargetType(d *schema.ResourceData, targetType string) string {

	switch targetType {
	case common.TargetTypeGcp:
		return d.Get("secret_id").(string)
	default:
		return d.Get("secret_name").(string)
	}
}

func validateUscSecretUpdateParams(d *schema.ResourceData) error {
	paramsMustNotUpdate := []string{
		"usc_name",
		"secret_name",
		"namespace",
	}
	return common.GetErrorOnUpdateParam(d, paramsMustNotUpdate)
}
