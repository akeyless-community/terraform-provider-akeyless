package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretPing() *schema.Resource {
	return &schema.Resource{
		Description: "Ping dynamic secret resource",
		Create:      resourceDynamicSecretPingCreate,
		Read:        resourceDynamicSecretPingRead,
		Update:      resourceDynamicSecretPingUpdate,
		Delete:      resourceDynamicSecretPingDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretPingImport,
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
			"ping_administrative_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Ping Federate administrative port",
				Default:     "9999",
			},
			"ping_atm_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set a specific Access Token Management (ATM) instance for the created OAuth Client by providing the ATM Id. If no explicit value is given, the default pingfederate server ATM will be set.",
			},
			"ping_authorization_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Ping Federate authorization port",
				Default:     "9031",
			},
			"ping_cert_subject_dn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The subject DN of the client certificate. If no explicit value is given, the producer will create CA certificate and matched client certificate and return it as value. Used in conjunction with ping-issuer-dn (relevant for CLIENT_TLS_CERTIFICATE authentication method)",
			},
			"ping_client_authentication_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "OAuth Client Authentication Type [CLIENT_SECRET, PRIVATE_KEY_JWT, CLIENT_TLS_CERTIFICATE]",
				Default:     "CLIENT_SECRET",
			},
			"ping_enforce_replay_prevention": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Determines whether PingFederate requires a unique signed JWT from the client for each action (relevant for PRIVATE_KEY_JWT authentication method) [true/false]",
				Default:     "false",
			},
			"ping_grant_types": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of OAuth client grant types [IMPLICIT, AUTHORIZATION_CODE, CLIENT_CREDENTIALS, TOKEN_EXCHANGE, REFRESH_TOKEN, ASSERTION_GRANTS, PASSWORD, RESOURCE_OWNER_CREDENTIALS]. If no explicit value is given, AUTHORIZATION_CODE will be selected as default.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"ping_issuer_dn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Issuer DN of trusted CA certificate that imported into Ping Federate server. You may select \"Trust Any\" to trust all the existing issuers in Ping Federate server. Used in conjunction with ping-cert-subject-dn (relevant for CLIENT_TLS_CERTIFICATE authentication method)",
			},
			"ping_jwks": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Base64-encoded JSON Web Key Set (JWKS). If no explicit value is given, the producer will create JWKs and matched signed JWT (Sign Algo: RS256) and return it as value (relevant for PRIVATE_KEY_JWT authentication method)",
			},
			"ping_jwks_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The URL of the JSON Web Key Set (JWKS). If no explicit value is given, the producer will create JWKs and matched signed JWT and return it as value (relevant for PRIVATE_KEY_JWT authentication method)",
			},
			"ping_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Ping Federate privileged user password",
			},
			"ping_privileged_user": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Ping Federate privileged user",
			},
			"ping_redirect_uris": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of URIs to which the OAuth authorization server may redirect the resource owner's user agent after authorization is obtained. At least one redirection URI is required for the AUTHORIZATION_CODE and IMPLICIT grant types.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"ping_restricted_scopes": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Limit the OAuth client to specific scopes list",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"ping_signing_algo": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The signing algorithm that the client must use to sign its request objects [RS256,RS384,RS512,ES256,ES384,ES512,PS256,PS384,PS512] If no explicit value is given, the client can use any of the supported signing algorithms (relevant for PRIVATE_KEY_JWT authentication method)",
			},
			"ping_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Ping URL",
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Target name",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The time from dynamic secret creation to expiration.",
				Default:     "60m",
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

func resourceDynamicSecretPingCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	pingAdministrativePort := d.Get("ping_administrative_port").(string)
	pingAtmId := d.Get("ping_atm_id").(string)
	pingAuthorizationPort := d.Get("ping_authorization_port").(string)
	pingCertSubjectDn := d.Get("ping_cert_subject_dn").(string)
	pingClientAuthenticationType := d.Get("ping_client_authentication_type").(string)
	pingEnforceReplayPrevention := d.Get("ping_enforce_replay_prevention").(string)
	pingGrantTypesSet := d.Get("ping_grant_types").(*schema.Set)
	pingGrantTypes := common.ExpandStringList(pingGrantTypesSet.List())
	pingIssuerDn := d.Get("ping_issuer_dn").(string)
	pingJwks := d.Get("ping_jwks").(string)
	pingJwksUrl := d.Get("ping_jwks_url").(string)
	pingPassword := d.Get("ping_password").(string)
	pingPrivilegedUser := d.Get("ping_privileged_user").(string)
	pingRedirectUrisSet := d.Get("ping_redirect_uris").(*schema.Set)
	pingRedirectUris := common.ExpandStringList(pingRedirectUrisSet.List())
	pingRestrictedScopesSet := d.Get("ping_restricted_scopes").(*schema.Set)
	pingRestrictedScopes := common.ExpandStringList(pingRestrictedScopesSet.List())
	pingSigningAlgo := d.Get("ping_signing_algo").(string)
	pingUrl := d.Get("ping_url").(string)
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.GatewayCreateProducerPing{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.PingAdministrativePort, pingAdministrativePort)
	common.GetAkeylessPtr(&body.PingAtmId, pingAtmId)
	common.GetAkeylessPtr(&body.PingAuthorizationPort, pingAuthorizationPort)
	common.GetAkeylessPtr(&body.PingCertSubjectDn, pingCertSubjectDn)
	common.GetAkeylessPtr(&body.PingClientAuthenticationType, pingClientAuthenticationType)
	common.GetAkeylessPtr(&body.PingEnforceReplayPrevention, pingEnforceReplayPrevention)
	common.GetAkeylessPtr(&body.PingGrantTypes, pingGrantTypes)
	common.GetAkeylessPtr(&body.PingIssuerDn, pingIssuerDn)
	common.GetAkeylessPtr(&body.PingJwks, pingJwks)
	common.GetAkeylessPtr(&body.PingJwksUrl, pingJwksUrl)
	common.GetAkeylessPtr(&body.PingPassword, pingPassword)
	common.GetAkeylessPtr(&body.PingPrivilegedUser, pingPrivilegedUser)
	common.GetAkeylessPtr(&body.PingRedirectUris, pingRedirectUris)
	common.GetAkeylessPtr(&body.PingRestrictedScopes, pingRestrictedScopes)
	common.GetAkeylessPtr(&body.PingSigningAlgo, pingSigningAlgo)
	common.GetAkeylessPtr(&body.PingUrl, pingUrl)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.GatewayCreateProducerPing(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretPingRead(d *schema.ResourceData, m interface{}) error {
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

func resourceDynamicSecretPingUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	deleteProtection := d.Get("delete_protection").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	pingAdministrativePort := d.Get("ping_administrative_port").(string)
	pingAtmId := d.Get("ping_atm_id").(string)
	pingAuthorizationPort := d.Get("ping_authorization_port").(string)
	pingCertSubjectDn := d.Get("ping_cert_subject_dn").(string)
	pingClientAuthenticationType := d.Get("ping_client_authentication_type").(string)
	pingEnforceReplayPrevention := d.Get("ping_enforce_replay_prevention").(string)
	pingGrantTypesSet := d.Get("ping_grant_types").(*schema.Set)
	pingGrantTypes := common.ExpandStringList(pingGrantTypesSet.List())
	pingIssuerDn := d.Get("ping_issuer_dn").(string)
	pingJwks := d.Get("ping_jwks").(string)
	pingJwksUrl := d.Get("ping_jwks_url").(string)
	pingPassword := d.Get("ping_password").(string)
	pingPrivilegedUser := d.Get("ping_privileged_user").(string)
	pingRedirectUrisSet := d.Get("ping_redirect_uris").(*schema.Set)
	pingRedirectUris := common.ExpandStringList(pingRedirectUrisSet.List())
	pingRestrictedScopesSet := d.Get("ping_restricted_scopes").(*schema.Set)
	pingRestrictedScopes := common.ExpandStringList(pingRestrictedScopesSet.List())
	pingSigningAlgo := d.Get("ping_signing_algo").(string)
	pingUrl := d.Get("ping_url").(string)
	targetName := d.Get("target_name").(string)
	userTtl := d.Get("user_ttl").(string)
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	itemCustomFields := d.Get("item_custom_fields").(map[string]interface{})

	body := akeyless_api.GatewayUpdateProducerPing{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.PingAdministrativePort, pingAdministrativePort)
	common.GetAkeylessPtr(&body.PingAtmId, pingAtmId)
	common.GetAkeylessPtr(&body.PingAuthorizationPort, pingAuthorizationPort)
	common.GetAkeylessPtr(&body.PingCertSubjectDn, pingCertSubjectDn)
	common.GetAkeylessPtr(&body.PingClientAuthenticationType, pingClientAuthenticationType)
	common.GetAkeylessPtr(&body.PingEnforceReplayPrevention, pingEnforceReplayPrevention)
	common.GetAkeylessPtr(&body.PingGrantTypes, pingGrantTypes)
	common.GetAkeylessPtr(&body.PingIssuerDn, pingIssuerDn)
	common.GetAkeylessPtr(&body.PingJwks, pingJwks)
	common.GetAkeylessPtr(&body.PingJwksUrl, pingJwksUrl)
	common.GetAkeylessPtr(&body.PingPassword, pingPassword)
	common.GetAkeylessPtr(&body.PingPrivilegedUser, pingPrivilegedUser)
	common.GetAkeylessPtr(&body.PingRedirectUris, pingRedirectUris)
	common.GetAkeylessPtr(&body.PingRestrictedScopes, pingRestrictedScopes)
	common.GetAkeylessPtr(&body.PingSigningAlgo, pingSigningAlgo)
	common.GetAkeylessPtr(&body.PingUrl, pingUrl)
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	if len(itemCustomFields) > 0 {
		fields := make(map[string]string)
		for k, v := range itemCustomFields {
			fields[k] = v.(string)
		}
		body.ItemCustomFields = &fields
	}

	_, resp, err := client.GatewayUpdateProducerPing(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretPingDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretPingImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretPingRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
