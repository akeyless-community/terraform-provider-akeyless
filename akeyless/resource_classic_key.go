// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceClassicKey() *schema.Resource {
	return &schema.Resource{
		Description: "Classic Key resource",
		Create:      resourceClassicKeyCreate,
		Read:        resourceClassicKeyRead,
		Update:      resourceClassicKeyUpdate,
		Delete:      resourceClassicKeyDelete,
		Importer: &schema.ResourceImporter{
			State: resourceClassicKeyImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Classic key name",
				ForceNew:    true,
			},
			"alg": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Key type; options: [AES128GCM, AES256GCM, AES128SIV, AES256SIV, RSA1024, RSA2048, RSA3072, RSA4096, EC256, EC384]",
			},
			"key_data": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Base64-encoded classic key value provided by user",
			},
			"cert_file_data": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "PEM Certificate in a Base64 format.",
			},
			"metadata": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Metadata about the classic key",
			},
			"tags": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"protection_key_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The name of the key that protects the classic key value (if empty, the account default key will be used)",
			},
			"target_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The target name to associate with this classic key",
			},
			"vault_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Name of the vault used (required for azure targets)",
			},
			"key_operations": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "A list of allowed operations for the key (required for azure targets)",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceClassicKeyCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	alg := d.Get("alg").(string)
	keyData := d.Get("key_data").(string)
	certFileData := d.Get("cert_file_data").(string)
	metadata := d.Get("metadata").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	protectionKeyName := d.Get("protection_key_name").(string)
	targetName := d.Get("target_name").(string)
	vaultName := d.Get("vault_name").(string)
	keyOperationsSet := d.Get("key_operations").(*schema.Set)
	keyOperations := common.ExpandStringList(keyOperationsSet.List())

	body := akeyless.CreateClassicKey{
		Name:  name,
		Alg:   alg,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.KeyData, keyData)
	common.GetAkeylessPtr(&body.CertFileData, certFileData)
	common.GetAkeylessPtr(&body.Metadata, metadata)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ProtectionKeyName, protectionKeyName)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.VaultName, vaultName)
	common.GetAkeylessPtr(&body.KeyOperations, keyOperations)

	_, _, err := client.CreateClassicKey(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceClassicKeyRead(d *schema.ResourceData, m interface{}) error {
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
				return nil
			}
			return fmt.Errorf("can't value: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get value: %v", err)
	}

	if rOut.ItemGeneralInfo.ClassicKeyDetails != nil {
		keyAlgorithm := rOut.ItemGeneralInfo.ClassicKeyDetails.KeyType
		if keyAlgorithm != nil {
			err = d.Set("alg", *keyAlgorithm)
			if err != nil {
				return err
			}
		}
	}
	if rOut.PublicValue != nil {
		err = d.Set("key_data", *rOut.PublicValue)
		if err != nil {
			return err
		}
	}
	if rOut.Certificates != nil {
		err = d.Set("cert_file_data", *rOut.Certificates)
		if err != nil {
			return err
		}
	}
	if rOut.ItemMetadata != nil {
		err = d.Set("metadata", *rOut.ItemMetadata)
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
	if rOut.ProtectionKeyName != nil {
		protectionKeyName := *rOut.ProtectionKeyName
		// ignore default protection key name
		if !strings.Contains(protectionKeyName, "__account-def-secrets-key__") {
			err = d.Set("protection_key_name", protectionKeyName)
			if err != nil {
				return err
			}
		}
	}
	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceClassicKeyUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	metadata := d.Get("metadata").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless.UpdateItem{
		Name:        name,
		Token:       &token,
		NewName:     akeyless.PtrString(name),
		NewMetadata: akeyless.PtrString(metadata),
	}

	add, remove, err := common.GetTagsForUpdate(d, name, token, tags, client)
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
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceClassicKeyDelete(d *schema.ResourceData, m interface{}) error {
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

func resourceClassicKeyImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
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
