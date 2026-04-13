// generated file
package akeyless

import (
	"context"
	"fmt"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
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
			"gcp_project_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GCP Project ID (Relevant only for GCP targets)",
			},
			"gcp_sm_regions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GCP Secret Manager regions to query for regional secrets (comma-separated, e.g., us-east1,us-west1). Max 12 regions. Required when listing with object-type=regional-secrets",
			},
			"usc_prefix": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Prefix for all secrets created in AWS Secrets Manager",
			},
			"use_prefix_as_filter": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "false",
				Description: "Whether to filter the USC secret list using the specified usc-prefix [true/false]",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
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
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
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
	gcpProjectId := d.Get("gcp_project_id").(string)
	gcpSmRegions := d.Get("gcp_sm_regions").(string)
	uscPrefix := d.Get("usc_prefix").(string)
	usePrefixAsFilter := d.Get("use_prefix_as_filter").(string)
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
	common.GetAkeylessPtr(&body.GcpProjectId, gcpProjectId)
	common.GetAkeylessPtr(&body.GcpSmRegions, gcpSmRegions)
	common.GetAkeylessPtr(&body.UscPrefix, uscPrefix)
	common.GetAkeylessPtr(&body.UsePrefixAsFilter, usePrefixAsFilter)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	if d.Get("item_custom_fields") != nil {
		itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
		if len(itemCustomFieldsMap) > 0 {
			itemCustomFields := make(map[string]string)
			for k, v := range itemCustomFieldsMap {
				itemCustomFields[k] = v.(string)
			}
			body.ItemCustomFields = &itemCustomFields
		}
	}

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
	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
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
				if gcpProjectId, ok := attr["gcp_project_id"]; ok {
					err := d.Set("gcp_project_id", gcpProjectId)
					if err != nil {
						return err
					}
				}
				if gcpSmRegions, ok := attr["gcp_sm_regions"]; ok {
					err := d.Set("gcp_sm_regions", gcpSmRegions)
					if err != nil {
						return err
					}
				}
				if uscPrefix, ok := attr["usc_prefix"]; ok {
					err := d.Set("usc_prefix", uscPrefix)
					if err != nil {
						return err
					}
				}
				if usePrefixAsFilter, ok := attr["use_prefix_as_filter"]; ok {
					err := d.Set("use_prefix_as_filter", usePrefixAsFilter)
					if err != nil {
						return err
					}
				}
			}
		}
	}

	if len(rOut.ItemCustomFieldsDetails) > 0 {
		itemCustomFields := make(map[string]string)
		for _, field := range rOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				itemCustomFields[*field.Name] = *field.Value
			}
		}
		err := d.Set("item_custom_fields", itemCustomFields)
		if err != nil {
			return err
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
		"gcp_project_id",
		"gcp_sm_regions",
		"usc_prefix",
		"use_prefix_as_filter",
		"item_custom_fields",
	}
	return common.GetErrorOnUpdateParam(d, paramsMustNotUpdate)
}
