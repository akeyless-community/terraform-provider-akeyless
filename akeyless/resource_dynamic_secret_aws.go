// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretAws() *schema.Resource {
	return &schema.Resource{
		Description: "AWS dynamic secret resource",
		Create:      resourceDynamicSecretAwsCreate,
		Read:        resourceDynamicSecretAwsRead,
		Update:      resourceDynamicSecretAwsUpdate,
		Delete:      resourceDynamicSecretAwsDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretAwsImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Dynamic secret name",
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of existing target to use in dynamic secret creation",
			},
			"aws_access_key_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Access Key ID",
			},
			"aws_access_secret_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Access Secret Key",
			},
			"access_mode": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "iam_user",
				Description: "The types of credentials to retrieve from AWS. Options:[iam_user,assume_role]",
			},
			"region": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Region",
				Default:     "us-east-2",
			},
			"aws_user_policies": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Policy ARN(s). Multiple values should be separated by comma",
			},
			"aws_user_groups": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "UserGroup name(s). Multiple values should be separated by comma",
			},
			"aws_role_arns": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS Role ARNs to be use in the Assume Role operation. Multiple values should be separated by comma",
			},
			"aws_user_console_access": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable AWS User console access",
				Default:     false,
			},
			"aws_user_programmatic_access": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable AWS User programmatic access",
				Default:     "true",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"password_length": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The length of the password to be generated",
			},
			"input_rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Password input rule definitions",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"output_rule": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "Password output rule definitions",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"use_capital_letters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Password must contain capital letters [true/false]",
			},
			"use_lower_letters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Password must contain lower case letters [true/false]",
			},
			"use_numbers": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Password must contain numbers [true/false]",
			},
			"use_special_characters": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Password must contain special characters [true/false]",
			},
			"encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Encrypt dynamic secret details with following key",
			},
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customize how temporary usernames are generated using go template",
			},
			"admin_rotation_interval_days": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Admin credentials rotation interval (days)",
			},
			"aws_external_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The AWS External ID associated with the AWS role (relevant only for assume_role mode)",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Protection from accidental deletion of this object [true/false]",
				Default:     "false",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"enable_admin_rotation": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Automatic admin credentials rotation",
			},
			"item_custom_fields": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Additional custom fields to associate with the item",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_certificate_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Secure Access",
			},
			"secure_access_bastion_issuer": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Bastion",
				Deprecated:  "use secure_access_certificate_issuer instead",
			},
			"secure_access_delay": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "The delay duration, in seconds, to wait after generating just-in-time credentials. Accepted range: 0-120 seconds",
			},
			"secure_access_web_proxy": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Web-Proxy via Akeyless's Secure Remote Access (SRA)",
			},
			"session_tags": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Session tags, space separated, relevant only for Assumed Role. Format: Key=name,Value=val Key=name2,Value=val2",
			},
			"transitive_tag_keys": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Transitive tag keys, space separated, relevant only for Assumed Role",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_aws_account_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The aws account id",
			},
			"secure_access_aws_native_cli": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "The aws native cli",
			},
			"secure_access_web_browsing": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Secure browser via Akeyless Web Access Bastion",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Default:     "true",
				Description: "Enable Web Secure Remote Access",
			},
			"secure_access_url": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"secure_access_aws_region": {
				Type:     schema.TypeString,
				Optional: true,
				Computed: true,
			},
			"use_gw_cloud_identity": {
				Type:        schema.TypeBool,
				Computed:    true,
				Description: "Use the GW's Cloud IAM",
			},
		},
	}
}

func resourceDynamicSecretAwsCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	awsAccessKeyId := d.Get("aws_access_key_id").(string)
	awsAccessSecretKey := d.Get("aws_access_secret_key").(string)
	accessMode := d.Get("access_mode").(string)
	region := d.Get("region").(string)
	awsUserPolicies := d.Get("aws_user_policies").(string)
	awsUserGroups := d.Get("aws_user_groups").(string)
	awsRoleArns := d.Get("aws_role_arns").(string)
	awsUserConsoleAccess := d.Get("aws_user_console_access").(bool)
	awsUserProgrammaticAccess := d.Get("aws_user_programmatic_access").(bool)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	useCapitalLetters := d.Get("use_capital_letters").(string)
	useLowerLetters := d.Get("use_lower_letters").(string)
	useNumbers := d.Get("use_numbers").(string)
	useSpecialCharacters := d.Get("use_special_characters").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	adminRotationIntervalDays := d.Get("admin_rotation_interval_days").(int)
	awsExternalId := d.Get("aws_external_id").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	enableAdminRotation := d.Get("enable_admin_rotation").(bool)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	if secureAccessCertificateIssuer == "" {
		secureAccessCertificateIssuer = d.Get("secure_access_bastion_issuer").(string)
	}
	secureAccessDelay := d.Get("secure_access_delay").(int)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)
	sessionTags := d.Get("session_tags").(string)
	transitiveTagKeys := d.Get("transitive_tag_keys").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessAwsAccountId := d.Get("secure_access_aws_account_id").(string)
	secureAccessAwsNativeCli := d.Get("secure_access_aws_native_cli").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.DynamicSecretCreateAws{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.AwsAccessKeyId, awsAccessKeyId)
	common.GetAkeylessPtr(&body.AwsAccessSecretKey, awsAccessSecretKey)
	common.GetAkeylessPtr(&body.AccessMode, accessMode)
	common.GetAkeylessPtr(&body.Region, region)
	common.GetAkeylessPtr(&body.AwsUserPolicies, awsUserPolicies)
	common.GetAkeylessPtr(&body.AwsUserGroups, awsUserGroups)
	common.GetAkeylessPtr(&body.AwsRoleArns, awsRoleArns)
	common.GetAkeylessPtr(&body.AwsUserConsoleAccess, awsUserConsoleAccess)
	common.GetAkeylessPtr(&body.AwsUserProgrammaticAccess, awsUserProgrammaticAccess)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.UseCapitalLetters, useCapitalLetters)
	common.GetAkeylessPtr(&body.UseLowerLetters, useLowerLetters)
	common.GetAkeylessPtr(&body.UseNumbers, useNumbers)
	common.GetAkeylessPtr(&body.UseSpecialCharacters, useSpecialCharacters)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	if adminRotationIntervalDays != 0 {
		body.AdminRotationIntervalDays = &[]int64{int64(adminRotationIntervalDays)}[0]
	}
	common.GetAkeylessPtr(&body.AwsExternalId, awsExternalId)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.EnableAdminRotation, enableAdminRotation)
	if len(itemCustomFields) > 0 {
		body.ItemCustomFields = &itemCustomFields
	}
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	if secureAccessDelay != 0 {
		body.SecureAccessDelay = &[]int64{int64(secureAccessDelay)}[0]
	}
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	common.GetAkeylessPtr(&body.SessionTags, sessionTags)
	common.GetAkeylessPtr(&body.TransitiveTagKeys, transitiveTagKeys)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessAwsAccountId, secureAccessAwsAccountId)
	common.GetAkeylessPtr(&body.SecureAccessAwsNativeCli, secureAccessAwsNativeCli)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, resp, err := client.DynamicSecretCreateAws(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretAwsRead(d *schema.ResourceData, m interface{}) error {
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

	if rOut.UserTtl != nil {
		err = d.Set("user_ttl", *rOut.UserTtl)
		if err != nil {
			return err
		}
	}
	if rOut.AwsAccessKeyId != nil {
		err = d.Set("aws_access_key_id", *rOut.AwsAccessKeyId)
		if err != nil {
			return err
		}
	}
	if rOut.AwsSecretAccessKey != nil {
		err = d.Set("aws_access_secret_key", *rOut.AwsSecretAccessKey)
		if err != nil {
			return err
		}
	}
	if rOut.AwsRegion != nil {
		err = d.Set("region", *rOut.AwsRegion)
		if err != nil {
			return err
		}
	}
	if rOut.UseGwCloudIdentity != nil {
		err = d.Set("use_gw_cloud_identity", *rOut.UseGwCloudIdentity)
		if err != nil {
			return err
		}
	}
	if rOut.Tags != nil {
		err = d.Set("tags", rOut.Tags)
		if err != nil {
			return err
		}
	}
	if rOut.AwsAccessMode != nil {
		err = d.Set("access_mode", *rOut.AwsAccessMode)
		if err != nil {
			return err
		}
	}
	if rOut.DynamicSecretKey != nil {
		err = common.SetDataByPrefixSlash(d, "encryption_key_name", *rOut.DynamicSecretKey, d.Get("encryption_key_name").(string))
		if err != nil {
			return err
		}
	}
	if rOut.UsernameTemplate != nil {
		err = d.Set("custom_username_template", *rOut.UsernameTemplate)
		if err != nil {
			return err
		}
	}
	if rOut.AwsUserConsoleAccess != nil {
		err = d.Set("aws_user_console_access", *rOut.AwsUserConsoleAccess)
		if err != nil {
			return err
		}
	}
	if rOut.AwsUserPolicies != nil {
		err = d.Set("aws_user_policies", *rOut.AwsUserPolicies)
		if err != nil {
			return err
		}
	}
	if rOut.AwsUserGroups != nil {
		err = d.Set("aws_user_groups", *rOut.AwsUserGroups)
		if err != nil {
			return err
		}
	}
	if rOut.AwsRoleArns != nil {
		err = d.Set("aws_role_arns", *rOut.AwsRoleArns)
		if err != nil {
			return err
		}
	}
	if rOut.AwsUserProgrammaticAccess != nil {
		err = d.Set("aws_user_programmatic_access", *rOut.AwsUserProgrammaticAccess)
		if err != nil {
			return err
		}
	}
	if rOut.AdminRotationIntervalDays != nil {
		err = d.Set("admin_rotation_interval_days", *rOut.AdminRotationIntervalDays)
		if err != nil {
			return err
		}
	}
	if rOut.AwsExternalId != nil {
		err = d.Set("aws_external_id", *rOut.AwsExternalId)
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
	if rOut.Metadata != nil {
		err = d.Set("description", *rOut.Metadata)
		if err != nil {
			return err
		}
	}
	if rOut.EnableAdminRotation != nil {
		err = d.Set("enable_admin_rotation", *rOut.EnableAdminRotation)
		if err != nil {
			return err
		}
	}
	if rOut.AwsSessionTags != nil {
		err = d.Set("session_tags", *rOut.AwsSessionTags)
		if err != nil {
			return err
		}
	}
	if rOut.AwsTransitiveTagKeys != nil {
		err = d.Set("transitive_tag_keys", *rOut.AwsTransitiveTagKeys)
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

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = common.SetDataByPrefixSlash(d, "target_name", targetName, d.Get("target_name").(string))
		if err != nil {
			return err
		}
	}
	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	if err = setAgenticRulesReadFields(d, rOut.AgenticRules); err != nil {
		return err
	}
	if err = setDynamicSecretPasswordPolicyReadFields(d, rOut); err != nil {
		return err
	}

	d.SetId(path)

	return nil
}

func resourceDynamicSecretAwsUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	awsAccessKeyId := d.Get("aws_access_key_id").(string)
	awsAccessSecretKey := d.Get("aws_access_secret_key").(string)
	accessMode := d.Get("access_mode").(string)
	region := d.Get("region").(string)
	awsUserPolicies := d.Get("aws_user_policies").(string)
	awsUserGroups := d.Get("aws_user_groups").(string)
	awsRoleArns := d.Get("aws_role_arns").(string)
	awsUserConsoleAccess := d.Get("aws_user_console_access").(bool)
	awsUserProgrammaticAccess := d.Get("aws_user_programmatic_access").(bool)
	passwordLength := d.Get("password_length").(string)
	inputRule := common.ExpandStringList(d.Get("input_rule").([]interface{}))
	outputRule := common.ExpandStringList(d.Get("output_rule").([]interface{}))
	useCapitalLetters := d.Get("use_capital_letters").(string)
	useLowerLetters := d.Get("use_lower_letters").(string)
	useNumbers := d.Get("use_numbers").(string)
	useSpecialCharacters := d.Get("use_special_characters").(string)
	producerEncryptionKeyName := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	adminRotationIntervalDays := d.Get("admin_rotation_interval_days").(int)
	awsExternalId := d.Get("aws_external_id").(string)
	deleteProtection := d.Get("delete_protection").(string)
	description := d.Get("description").(string)
	enableAdminRotation := d.Get("enable_admin_rotation").(bool)
	itemCustomFieldsMap := d.Get("item_custom_fields").(map[string]interface{})
	itemCustomFields := make(map[string]string)
	for k, v := range itemCustomFieldsMap {
		itemCustomFields[k] = v.(string)
	}
	secureAccessCertificateIssuer := d.Get("secure_access_certificate_issuer").(string)
	if secureAccessCertificateIssuer == "" {
		secureAccessCertificateIssuer = d.Get("secure_access_bastion_issuer").(string)
	}
	secureAccessDelay := d.Get("secure_access_delay").(int)
	secureAccessWebProxy := d.Get("secure_access_web_proxy").(bool)
	sessionTags := d.Get("session_tags").(string)
	transitiveTagKeys := d.Get("transitive_tag_keys").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessAwsAccountId := d.Get("secure_access_aws_account_id").(string)
	secureAccessAwsNativeCli := d.Get("secure_access_aws_native_cli").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless_api.DynamicSecretUpdateAws{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.AwsAccessKeyId, awsAccessKeyId)
	common.GetAkeylessPtr(&body.AwsAccessSecretKey, awsAccessSecretKey)
	common.GetAkeylessPtr(&body.AccessMode, accessMode)
	common.GetAkeylessPtr(&body.Region, region)
	common.GetAkeylessPtr(&body.AwsUserPolicies, awsUserPolicies)
	common.GetAkeylessPtr(&body.AwsUserGroups, awsUserGroups)
	common.GetAkeylessPtr(&body.AwsRoleArns, awsRoleArns)
	common.GetAkeylessPtr(&body.AwsUserConsoleAccess, awsUserConsoleAccess)
	common.GetAkeylessPtr(&body.AwsUserProgrammaticAccess, awsUserProgrammaticAccess)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.InputRule, inputRule)
	common.GetAkeylessPtr(&body.OutputRule, outputRule)
	common.GetAkeylessPtr(&body.UseCapitalLetters, useCapitalLetters)
	common.GetAkeylessPtr(&body.UseLowerLetters, useLowerLetters)
	common.GetAkeylessPtr(&body.UseNumbers, useNumbers)
	common.GetAkeylessPtr(&body.UseSpecialCharacters, useSpecialCharacters)
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	if adminRotationIntervalDays != 0 {
		body.AdminRotationIntervalDays = &[]int64{int64(adminRotationIntervalDays)}[0]
	}
	common.GetAkeylessPtr(&body.AwsExternalId, awsExternalId)
	common.GetAkeylessPtr(&body.DeleteProtection, deleteProtection)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.EnableAdminRotation, enableAdminRotation)
	if len(itemCustomFields) > 0 {
		body.ItemCustomFields = &itemCustomFields
	}
	common.GetAkeylessPtr(&body.SecureAccessCertificateIssuer, secureAccessCertificateIssuer)
	if secureAccessDelay != 0 {
		body.SecureAccessDelay = &[]int64{int64(secureAccessDelay)}[0]
	}
	common.GetAkeylessPtr(&body.SecureAccessWebProxy, secureAccessWebProxy)
	common.GetAkeylessPtr(&body.SessionTags, sessionTags)
	common.GetAkeylessPtr(&body.TransitiveTagKeys, transitiveTagKeys)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessAwsAccountId, secureAccessAwsAccountId)
	common.GetAkeylessPtr(&body.SecureAccessAwsNativeCli, secureAccessAwsNativeCli)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, resp, err := client.DynamicSecretUpdateAws(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update dynamic secret", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretAwsDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretAwsImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretAwsRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
