// generated file
package akeyless

import (
	"context"
	"fmt"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretTmpCreds() *schema.Resource {
	return &schema.Resource{
		Description: "Manage dynamic secret temporary credentials",
		Create:      resourceDynamicSecretTmpCredsUpdate,
		Read:        resourceDynamicSecretTmpCredsRead,
		Update:      resourceDynamicSecretTmpCredsUpdate,
		Delete:      resourceDynamicSecretTmpCredsDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretTmpCredsImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
			},
			"tmp_creds_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Tmp Creds ID",
			},
			"new_ttl_min": {
				Type:        schema.TypeInt,
				Required:    true,
				Description: "New TTL in minutes",
			},
			"host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Host",
			},
			"input_rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Input rule definitions",
			},
			"output_rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Elem:        &schema.Schema{Type: schema.TypeString},
				Description: "Output rule definitions",
			},
		},
	}
}

func resourceDynamicSecretTmpCredsUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	tmpCredsId := d.Get("tmp_creds_id").(string)
	host := d.Get("host").(string)
	newTtlMin := d.Get("new_ttl_min").(int)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))

	body := akeyless_api.DynamicSecretTmpCredsUpdate{
		Name:       name,
		TmpCredsId: tmpCredsId,
		Host:       host,
		NewTtlMin:  int64(newTtlMin),
		Token:      &token,
	}
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)

	resp, err := client.DynamicSecretTmpCredsUpdate(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update tmp creds", resp, err)
	}

	d.SetId(name + "/" + tmpCredsId)

	return nil
}

func resourceDynamicSecretTmpCredsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	id := d.Id()
	name, tmpCredsId, err := parseTmpCredsID(id)
	if err != nil {
		return err
	}

	body := akeyless_api.DynamicSecretTmpCredsGet{
		Name:  name,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretTmpCredsGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get tmp creds", res, err)
	}

	var found bool
	for _, entry := range rOut {
		if entry.Id != nil && *entry.Id == tmpCredsId {
			found = true

			// We don't read back `host` and `new_ttl_min` because they are inputs to the action,
			// and the API response might contain different values (e.g. remaining TTL, or JSON host config)
			// which would cause a continuous diff in Terraform.
			break
		}
	}

	if !found {
		d.SetId("")
		return nil
	}

	err = d.Set("name", name)
	if err != nil {
		return err
	}
	err = d.Set("tmp_creds_id", tmpCredsId)
	if err != nil {
		return err
	}

	return nil
}

func resourceDynamicSecretTmpCredsDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	id := d.Id()
	name, tmpCredsId, err := parseTmpCredsID(id)
	if err != nil {
		return err
	}

	body := akeyless_api.DynamicSecretTmpCredsDelete{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TmpCredsId, tmpCredsId)

	resp, err := client.DynamicSecretTmpCredsDelete(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't delete tmp creds", resp, err)
	}

	return nil
}

func resourceDynamicSecretTmpCredsImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()
	name, tmpCredsId, err := parseTmpCredsID(id)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", name)
	if err != nil {
		return nil, err
	}
	err = d.Set("tmp_creds_id", tmpCredsId)
	if err != nil {
		return nil, err
	}

	err = resourceDynamicSecretTmpCredsRead(d, m)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func parseTmpCredsID(id string) (string, string, error) {
	lastSlashIndex := strings.LastIndex(id, "/")
	if lastSlashIndex == -1 || lastSlashIndex == 0 || lastSlashIndex == len(id)-1 {
		return "", "", fmt.Errorf("unexpected format of ID (%s), expected name/tmp_creds_id", id)
	}
	return id[:lastSlashIndex], id[lastSlashIndex+1:], nil
}
