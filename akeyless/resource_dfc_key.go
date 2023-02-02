package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDfcKey() *schema.Resource {
	return &schema.Resource{
		Description: "DFC Key resource ",
		Create:      resourceDfcKeyCreate,
		Read:        resourceDfcKeyRead,
		Update:      resourceDfcKeyUpdate,
		Delete:      resourceDfcKeyDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDfcKeyImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "DFCKey name",
				ForceNew:    true,
			},
			"alg": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "DFCKey type; options: [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048, RSA3072, RSA4096]",
			},
			"metadata": {
				Type:       schema.TypeString,
				Optional:   true,
				Deprecated: "Deprecated: Use description instead",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"tags": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this DFC key. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"customer_frg_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The customer fragment ID that will be used to create the DFC key (if empty, the key will be created independently of a customer fragment)",
			},
		},
	}
}

func resourceDfcKeyCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	alg := d.Get("alg").(string)
	metadata := d.Get("metadata").(string)
	description := d.Get("description").(string)
	tagSet := d.Get("tags").(*schema.Set)
	tag := common.ExpandStringList(tagSet.List())
	customerFrgId := d.Get("customer_frg_id").(string)

	body := akeyless.CreateDFCKey{
		Name:  name,
		Alg:   alg,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.SplitLevel, 3)
	common.GetAkeylessPtr(&body.Metadata, metadata)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tag, tag)
	common.GetAkeylessPtr(&body.CustomerFrgId, customerFrgId)

	_, _, err := client.CreateDFCKey(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create key: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create key: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDfcKeyRead(d *schema.ResourceData, m interface{}) error {

	path := d.Id()

	rOut, err := getDfcKey(d, m)
	if err != nil || rOut == nil {
		return err
	}

	if rOut.ItemMetadata != nil {
		err = d.Set("description", *rOut.ItemMetadata)
		if err != nil {
			return err
		}
	}

	if rOut.ItemType != nil {
		err = d.Set("alg", *rOut.ItemType)
		if err != nil {
			return err
		}
	}

	if rOut.ItemTags != nil {
		err = d.Set("tags", *rOut.ItemTags)
		if err != nil {
			return err
		}
	}
	if rOut.CustomerFragmentId != nil {
		err = d.Set("customer_frg_id", *rOut.CustomerFragmentId)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceDfcKeyUpdate(d *schema.ResourceData, m interface{}) error {

	err := validateDfcKeyUpdateParams(d)
	if err != nil {
		return fmt.Errorf("can't update: %v", err)
	}

	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	metadata := d.Get("metadata").(string)
	description := d.Get("description").(string)
	tagSet := d.Get("tags").(*schema.Set)
	tagList := common.ExpandStringList(tagSet.List())

	body := akeyless.UpdateItem{
		Name:  name,
		Token: &token,
	}

	common.GetAkeylessPtr(&body.NewMetadata, metadata)
	common.GetAkeylessPtr(&body.Description, description)

	add, remove, err := common.GetTagsForUpdate(d, name, token, tagList, client)
	if err == nil {
		if len(add) > 0 {
			common.GetAkeylessPtr(&body.AddTag, add)
		}
		if len(remove) > 0 {
			common.GetAkeylessPtr(&body.RmTag, remove)
		}
	}

	_, _, err = client.UpdateItem(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDfcKeyDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteItem{
		Token:             &token,
		Name:              path,
		DeleteImmediately: akeyless.PtrBool(true),
		DeleteInDays:      akeyless.PtrInt64(-1),
	}

	ctx := context.Background()
	_, _, err := client.DeleteItem(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceDfcKeyImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.DescribeItem{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func getDfcKey(d *schema.ResourceData, m interface{}) (*akeyless.Item, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.DescribeItem{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil, nil
			}
			return nil, fmt.Errorf("can't get key: %v", string(apiErr.Body()))
		}
		return nil, fmt.Errorf("can't get key: %v", err)
	}

	return &rOut, nil
}

func validateDfcKeyUpdateParams(d *schema.ResourceData) error {
	paramsMustNotUpdate := []string{"alg"}
	return common.GetErrorOnUpdateParam(d, paramsMustNotUpdate)
}
