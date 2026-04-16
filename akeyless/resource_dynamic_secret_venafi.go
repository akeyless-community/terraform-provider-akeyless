package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretVenafi() *schema.Resource {
	return &schema.Resource{
		Description: "Venafi dynamic secret resource",
		Create:      resourceDynamicSecretVenafiCreate,
		Read:        resourceDynamicSecretVenafiRead,
		Update:      resourceDynamicSecretVenafiUpdate,
		Delete:      resourceDynamicSecretVenafiDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretVenafiImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic secret name",
				ForceNew:    true,
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Add tags attached to this object",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"admin_rotation_interval_days": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Admin credentials rotation interval (days)",
				Default:     0,
			},
			"allow_subdomains": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Allow subdomains",
			},
			"allowed_domains": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Allowed domains",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"auto_generated_folder": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Auto generated folder",
			},
			"enable_admin_rotation": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Automatic admin credentials rotation",
				Default:     false,
			},
			"root_first_in_chain": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Root first in chain",
			},
			"sign_using_akeyless_pki": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Use Akeyless PKI issuer or Venafi issuer",
			},
			"signer_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Signer key name",
			},
			"store_private_key": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Store private key",
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Target name",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL in time.Duration format (2160h / 129600m / etc...). When using sign-using-akeyless-pki certificates created will have this validity period, otherwise the user-ttl is taken from the Validity Period field of the Zone's' Issuing Template. When using cert-manager it is advised to have a TTL of above 60 days (1440h). For more information - https://cert-manager.io/docs/usage/certificate/",
				Default:     "2160h",
			},
			"venafi_access_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Venafi Access Token to use to access the TPP environment (Relevant when using TPP)",
			},
			"venafi_api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Venafi API key",
			},
			"venafi_baseurl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Venafi Baseurl",
			},
			"venafi_client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Venafi Client ID that was used when the access token was generated",
				Default:     "akeyless",
			},
			"venafi_refresh_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Venafi Refresh Token to use when the Access Token is expired (Relevant when using TPP)",
			},
			"venafi_use_tpp": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Venafi using TPP",
			},
			"venafi_zone": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Venafi Zone",
			},
			"producer_encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Dynamic producer encryption key",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceDynamicSecretVenafiCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	adminRotationIntervalDays := d.Get("admin_rotation_interval_days").(int)
	allowSubdomains := d.Get("allow_subdomains").(bool)
	allowedDomainsSet := d.Get("allowed_domains").(*schema.Set)
	allowedDomains := common.ExpandStringList(allowedDomainsSet.List())
	autoGeneratedFolder := d.Get("auto_generated_folder").(string)
	enableAdminRotation := d.Get("enable_admin_rotation").(bool)
	rootFirstInChain := d.Get("root_first_in_chain").(bool)
	signUsingAkeylessPki := d.Get("sign_using_akeyless_pki").(bool)
	signerKeyName := d.Get("signer_key_name").(string)
	storePrivateKey := d.Get("store_private_key").(bool)
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	venafiAccessToken := d.Get("venafi_access_token").(string)
	venafiApiKey := d.Get("venafi_api_key").(string)
	venafiBaseurl := d.Get("venafi_baseurl").(string)
	venafiClientId := d.Get("venafi_client_id").(string)
	venafiRefreshToken := d.Get("venafi_refresh_token").(string)
	venafiUseTpp := d.Get("venafi_use_tpp").(bool)
	venafiZone := d.Get("venafi_zone").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.GatewayCreateProducerVenafi{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.AdminRotationIntervalDays, int64(adminRotationIntervalDays))
	common.GetAkeylessPtr(&body.AllowSubdomains, allowSubdomains)
	common.GetAkeylessPtr(&body.AllowedDomains, allowedDomains)
	common.GetAkeylessPtr(&body.AutoGeneratedFolder, autoGeneratedFolder)
	common.GetAkeylessPtr(&body.EnableAdminRotation, enableAdminRotation)
	common.GetAkeylessPtr(&body.RootFirstInChain, rootFirstInChain)
	common.GetAkeylessPtr(&body.SignUsingAkeylessPki, signUsingAkeylessPki)
	common.GetAkeylessPtr(&body.SignerKeyName, signerKeyName)
	common.GetAkeylessPtr(&body.StorePrivateKey, storePrivateKey)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.VenafiAccessToken, venafiAccessToken)
	common.GetAkeylessPtr(&body.VenafiApiKey, venafiApiKey)
	common.GetAkeylessPtr(&body.VenafiBaseurl, venafiBaseurl)
	common.GetAkeylessPtr(&body.VenafiClientId, venafiClientId)
	common.GetAkeylessPtr(&body.VenafiRefreshToken, venafiRefreshToken)
	common.GetAkeylessPtr(&body.VenafiUseTpp, venafiUseTpp)
	common.GetAkeylessPtr(&body.VenafiZone, venafiZone)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.GatewayCreateProducerVenafi(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretVenafiRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get dynamic secret value", res, err)
	}

	deleteProtectionVal := "false"
	if rOut.DeleteProtection != nil {
		deleteProtectionVal = strconv.FormatBool(*rOut.DeleteProtection)
	}
	err = d.Set("delete_protection", deleteProtectionVal)
	if err != nil {
		return err
	}
	if rOut.Tags != nil {
		err = d.Set("tags", rOut.Tags)
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

	if rOut.UserTtl != nil {
		err = d.Set("user_ttl", *rOut.UserTtl)
		if err != nil {
			return err
		}
	}

	if rOut.DynamicSecretKey != nil {
		err = d.Set("producer_encryption_key_name", *rOut.DynamicSecretKey)
		if err != nil {
			return err
		}
	}

	if len(rOut.ItemCustomFieldsDetails) > 0 {
		customFields := make(map[string]string)
		for _, field := range rOut.ItemCustomFieldsDetails {
			if field.Name != nil && field.Value != nil {
				customFields[*field.Name] = *field.Value
			}
		}
		if len(customFields) > 0 {
			err = d.Set("item_custom_fields", customFields)
			if err != nil {
				return err
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceDynamicSecretVenafiUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	adminRotationIntervalDays := d.Get("admin_rotation_interval_days").(int)
	allowSubdomains := d.Get("allow_subdomains").(bool)
	allowedDomainsSet := d.Get("allowed_domains").(*schema.Set)
	allowedDomains := common.ExpandStringList(allowedDomainsSet.List())
	autoGeneratedFolder := d.Get("auto_generated_folder").(string)
	enableAdminRotation := d.Get("enable_admin_rotation").(bool)
	rootFirstInChain := d.Get("root_first_in_chain").(bool)
	signUsingAkeylessPki := d.Get("sign_using_akeyless_pki").(bool)
	signerKeyName := d.Get("signer_key_name").(string)
	storePrivateKey := d.Get("store_private_key").(bool)
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	venafiAccessToken := d.Get("venafi_access_token").(string)
	venafiApiKey := d.Get("venafi_api_key").(string)
	venafiBaseurl := d.Get("venafi_baseurl").(string)
	venafiClientId := d.Get("venafi_client_id").(string)
	venafiRefreshToken := d.Get("venafi_refresh_token").(string)
	venafiUseTpp := d.Get("venafi_use_tpp").(bool)
	venafiZone := d.Get("venafi_zone").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.GatewayUpdateProducerVenafi{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.AdminRotationIntervalDays, int64(adminRotationIntervalDays))
	common.GetAkeylessPtr(&body.AllowSubdomains, allowSubdomains)
	common.GetAkeylessPtr(&body.AllowedDomains, allowedDomains)
	common.GetAkeylessPtr(&body.AutoGeneratedFolder, autoGeneratedFolder)
	common.GetAkeylessPtr(&body.EnableAdminRotation, enableAdminRotation)
	common.GetAkeylessPtr(&body.RootFirstInChain, rootFirstInChain)
	common.GetAkeylessPtr(&body.SignUsingAkeylessPki, signUsingAkeylessPki)
	common.GetAkeylessPtr(&body.SignerKeyName, signerKeyName)
	common.GetAkeylessPtr(&body.StorePrivateKey, storePrivateKey)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.VenafiAccessToken, venafiAccessToken)
	common.GetAkeylessPtr(&body.VenafiApiKey, venafiApiKey)
	common.GetAkeylessPtr(&body.VenafiBaseurl, venafiBaseurl)
	common.GetAkeylessPtr(&body.VenafiClientId, venafiClientId)
	common.GetAkeylessPtr(&body.VenafiRefreshToken, venafiRefreshToken)
	common.GetAkeylessPtr(&body.VenafiUseTpp, venafiUseTpp)
	common.GetAkeylessPtr(&body.VenafiZone, venafiZone)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.GatewayUpdateProducerVenafi(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretVenafiDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretVenafiImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretVenafiRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
