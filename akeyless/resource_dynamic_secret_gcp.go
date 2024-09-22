// generated fule
package akeyless

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretGcp() *schema.Resource {
	return &schema.Resource{
		Description: "Google Cloud Provider (GCP) dynamic secret resource",
		Create:      resourceDynamicSecretGcpCreate,
		Read:        resourceDynamicSecretGcpRead,
		Update:      resourceDynamicSecretGcpUpdate,
		Delete:      resourceDynamicSecretGcpDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretGcpImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of existing target to use in dynamic secret creation",
			},
			"gcp_sa_email": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "GCP service account email",
			},
			"gcp_cred_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Credentials type, options are [token, key]",
				Default:     "token",
			},
			"gcp_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base64-encoded service account private key text",
			},
			"gcp_token_scopes": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Access token scopes list, e.g. scope1,scope2",
			},
			"gcp_key_algo": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Service account key algorithm, e.g. KEY_ALG_RSA_1024",
			},
			"service_account_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "fixed",
				Description: "The type of the gcp dynamic secret. Options[fixed, dynamic]",
			},
			"role_binding": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Role binding definitions in json format",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL (<=60m for access token)",
				Default:     "60m",
			},
			"encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Encrypt dynamic secret details with following key",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: --tag Tag1 --tag Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this item, [true/false]",
			},
		},
	}
}

func resourceDynamicSecretGcpCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	gcpSaEmail := d.Get("gcp_sa_email").(string)
	gcpCredType := d.Get("gcp_cred_type").(string)
	gcpKey := d.Get("gcp_key").(string)
	gcpTokenScopes := d.Get("gcp_token_scopes").(string)
	gcpKeyAlgo := d.Get("gcp_key_algo").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	serviceAccountType := d.Get("service_account_type").(string)
	roleBinding := d.Get("role_binding").(string)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.DynamicSecretCreateGcp{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.GcpSaEmail, gcpSaEmail)
	common.GetAkeylessPtr(&body.GcpCredType, gcpCredType)
	common.GetAkeylessPtr(&body.GcpKey, gcpKey)
	common.GetAkeylessPtr(&body.GcpTokenScopes, gcpTokenScopes)
	common.GetAkeylessPtr(&body.GcpKeyAlgo, gcpKeyAlgo)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.ServiceAccountType, serviceAccountType)
	common.GetAkeylessPtr(&body.RoleBinding, roleBinding)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.DynamicSecretCreateGcp(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretGcpRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
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
	if rOut.GcpKeyAlgo != nil {
		err = d.Set("gcp_key_algo", *rOut.GcpKeyAlgo)
		if err != nil {
			return err
		}
	}
	if rOut.UserTtl != nil {
		err = d.Set("user_ttl", *rOut.UserTtl)
		if err != nil {
			return err
		}
	}
	if rOut.Tags != nil {
		err = d.Set("tags", *rOut.Tags)
		if err != nil {
			return err
		}
	}

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = d.Set("target_name", targetName)
		if err != nil {
			return err
		}
	}
	if rOut.GcpServiceAccountEmail != nil {
		err = d.Set("gcp_sa_email", *rOut.GcpServiceAccountEmail)
		if err != nil {
			return err
		}
	}
	if rOut.GcpTokenType != nil {
		err = d.Set("gcp_cred_type", *rOut.GcpTokenType)
		if err != nil {
			return err
		}
	}
	if rOut.GcpServiceAccountKey != nil {
		gcp_key_base64 := base64.StdEncoding.EncodeToString([]byte(*rOut.GcpServiceAccountKey))
		err = d.Set("gcp_key", gcp_key_base64)
		if err != nil {
			return err
		}
	}
	if rOut.GcpTokenScope != nil {
		err = d.Set("gcp_token_scopes", *rOut.GcpTokenScope)
		if err != nil {
			return err
		}
	}
	if rOut.DynamicSecretKey != nil {
		err = d.Set("encryption_key_name", *rOut.DynamicSecretKey)
		if err != nil {
			return err
		}
	}
	if rOut.GcpServiceAccountType != nil {
		err = d.Set("service_account_type", *rOut.GcpServiceAccountType)
		if err != nil {
			return err
		}
	}
	if rOut.GcpRoleBindings != nil {
		bytes, err := json.Marshal(*rOut.GcpRoleBindings)
		if err != nil {
			return err
		}

		err = d.Set("role_binding", string(bytes))
		if err != nil {
			return err
		}
	}
	if rOut.DeleteProtection != nil {
		err = d.Set("delete_protection", strconv.FormatBool(*rOut.DeleteProtection))
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceDynamicSecretGcpUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	gcpSaEmail := d.Get("gcp_sa_email").(string)
	gcpCredType := d.Get("gcp_cred_type").(string)
	gcpKey := d.Get("gcp_key").(string)
	gcpTokenScopes := d.Get("gcp_token_scopes").(string)
	gcpKeyAlgo := d.Get("gcp_key_algo").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	serviceAccountType := d.Get("service_account_type").(string)
	roleBinding := d.Get("role_binding").(string)
	deleteProtection := d.Get("delete_protection").(string)

	body := akeyless_api.DynamicSecretUpdateGcp{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.GcpSaEmail, gcpSaEmail)
	common.GetAkeylessPtr(&body.GcpCredType, gcpCredType)
	common.GetAkeylessPtr(&body.GcpKey, gcpKey)
	common.GetAkeylessPtr(&body.GcpTokenScopes, gcpTokenScopes)
	common.GetAkeylessPtr(&body.GcpKeyAlgo, gcpKeyAlgo)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.ServiceAccountType, serviceAccountType)
	common.GetAkeylessPtr(&body.RoleBinding, roleBinding)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)

	_, _, err := client.DynamicSecretUpdateGcp(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretGcpDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretGcpImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretGcpRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
