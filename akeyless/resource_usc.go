// generated file
package akeyless

import (
	"context"
	"fmt"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceUsc() *schema.Resource {
	return &schema.Resource{
		Description: "Universal Secrets Connector resource",
		Create:      resourceUscCreate,
		Read:        resourceUscRead,
		Update:      resourceUscUpdate,
		Delete:      resourceUscDelete,
		Importer: &schema.ResourceImporter{
			State: resourceUscImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Universal Secrets Connector name",
				ForceNew:    true,
			},
			"target_to_associate": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target Universal Secrets Connector to connect",
			},
			"azure_kv_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure Key Vault name (Relevant only for Azure targets)",
			},
			"k8s_namespace": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "K8s namespace (Relevant to Kubernetes targets)",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the Universal Secrets Connector",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this Universal Secrets Connector",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Protection from accidental deletion of this object, [true/false]",
			},
		},
	}
}

func resourceUscCreate(d *schema.ResourceData, m any) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetToAssociate := d.Get("target_to_associate").(string)
	azureKvName := d.Get("azure_kv_name").(string)
	k8sNamespace := d.Get("k8s_namespace").(string)
	description := d.Get("description").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.CreateUSC{
		Name:              name,
		TargetToAssociate: targetToAssociate,
		Token:             &token,
	}
	common.GetAkeylessPtr(&body.AzureKvName, azureKvName)
	common.GetAkeylessPtr(&body.K8sNamespace, k8sNamespace)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, resp, err := client.CreateUSC(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create usc", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceUscRead(d *schema.ResourceData, m any) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DescribeItem{
		Name:  path,
		Token: &token,
	}

	rOut, resp, err := client.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get usc", resp, err)
	}

	if rOut.ItemMetadata != nil {
		err := d.Set("description", *rOut.ItemMetadata)
		if err != nil {
			return err
		}
	}
	if rOut.ItemTags != nil {
		err := d.Set("tags", rOut.ItemTags)
		if err != nil {
			return err
		}
	}
	if rOut.DeleteProtection != nil {
		err := d.Set("delete_protection", strconv.FormatBool(*rOut.DeleteProtection))
		if err != nil {
			return err
		}
	}

	if rOut.ItemTargetsAssoc != nil {

		assocs := rOut.ItemTargetsAssoc
		if len(assocs) > 0 {
			assoc := assocs[0]
			if assoc.TargetName != nil {
				err := common.SetDataByPrefixSlash(d, "target_to_associate", *assoc.TargetName, d.Get("target_to_associate").(string))
				if err != nil {
					return err
				}
			}
			if assoc.Attributes != nil {
				attr := *assoc.Attributes
				if k8sNamespace, ok := attr["k8s_namespace"]; ok {
					err := d.Set("k8s_namespace", k8sNamespace)
					if err != nil {
						return err
					}
				}
				if azureKvName, ok := attr["azure_vault"]; ok {
					err := d.Set("azure_kv_name", azureKvName)
					if err != nil {
						return err
					}
				}
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceUscUpdate(d *schema.ResourceData, m any) error {

	err := validateUscUpdateParams(d)
	if err != nil {
		return fmt.Errorf("can't update: %v", err)
	}

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	deleteProtection := d.Get("delete_protection").(string)

	tagsSet := d.Get("tags").(*schema.Set)
	tagList := common.ExpandStringList(tagsSet.List())

	body := akeyless_api.UpdateItem{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	add, remove, err := common.GetTagsForUpdate(d, name, token, tagList, client)
	if err == nil {
		if len(add) > 0 {
			common.GetAkeylessPtr(&body.AddTag, add)
		}
		if len(remove) > 0 {
			common.GetAkeylessPtr(&body.RmTag, remove)
		}
	}

	_, resp, err := client.UpdateItem(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update usc", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceUscDelete(d *schema.ResourceData, m any) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.DeleteItem{
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

func resourceUscImport(d *schema.ResourceData, m any) ([]*schema.ResourceData, error) {
	id := d.Id()

	err := resourceUscRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

func validateUscUpdateParams(d *schema.ResourceData) error {
	paramsMustNotUpdate := []string{
		"target_to_associate",
		"azure_kv_name",
		"k8s_namespace",
	}
	return common.GetErrorOnUpdateParam(d, paramsMustNotUpdate)
}
