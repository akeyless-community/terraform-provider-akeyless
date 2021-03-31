package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceStaticSecret() *schema.Resource {
	return &schema.Resource{
		Description: "Static secret Resource",
		Create:      resourceStaticSecretCreate,
		Read:        resourceStaticSecretRead,
		Update:      resourceStaticSecretUpdate,
		Delete:      resourceStaticSecretDelete,
		Importer: &schema.ResourceImporter{
			State: resourceStaticSecretImport,
		},
		Schema: map[string]*schema.Schema{
			"path": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "The path where the secret will be stored.",
			},
			"value": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				Description: "The secret content.",
			},
			"version": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "The version of the secret.",
			},
			"protection_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The version of the secret.",
			},
		},
	}
}

func resourceStaticSecretCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Get("path").(string)
	value := d.Get("value").(string)
	ProtectionKey := d.Get("protection_key").(string)

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	body := akeyless.CreateSecret{
		Name:  path,
		Value: value,
		Token: &token,
	}
	if ProtectionKey != "" {
		body.ProtectionKey = akeyless.PtrString(ProtectionKey)
	}

	_, _, err := client.CreateSecret(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	item := akeyless.DescribeItem{
		Name:         path,
		ShowVersions: akeyless.PtrBool(true),
		Token:        &token,
	}

	itemOut, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return err
	}

	version := itemOut.LastVersion

	err = d.Set("version", *version)
	if err != nil {
		return err
	}

	pk := itemOut.ProtectionKeyName
	err = d.Set("protection_key", *pk)
	if err != nil {
		return err
	}

	d.SetId(path)

	return nil
}

func resourceStaticSecretRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	gsvBody := akeyless.GetSecretValue{
		Names: []string{path},
		Token: &token,
	}

	gsvOut, res, err := client.GetSecretValue(ctx).Body(gsvBody).Execute()

	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The secret was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't get Secret value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get Secret value: %v", err)
	}

	if gsvOut[path] != d.Get("value") {
		// The secret has been updated outside of the current Terraform workspace
		item := akeyless.DescribeItem{
			Name:         path,
			ShowVersions: akeyless.PtrBool(true),
			Token:        &token,
		}

		itemOut, _, err := client.DescribeItem(ctx).Body(item).Execute()
		if err != nil {
			return err
		}

		version := itemOut.LastVersion

		err = d.Set("version", *version)
		if err != nil {
			return err
		}

		pk := itemOut.ProtectionKeyName
		err = d.Set("protection_key", *pk)
		if err != nil {
			return err
		}

		err = d.Set("value", gsvOut[path])
		if err != nil {
			return err
		}
	}

	return nil
}

func resourceStaticSecretUpdate(d *schema.ResourceData, m interface{}) error {
	return resourceStaticSecretCreate(d, m)
}

func resourceStaticSecretDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteItem{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteItem(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceStaticSecretImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.DescribeItem{
		Name:         path,
		ShowVersions: akeyless.PtrBool(true),
		Token:        &token,
	}

	ctx := context.Background()
	_, _, err := client.DescribeItem(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("path", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
