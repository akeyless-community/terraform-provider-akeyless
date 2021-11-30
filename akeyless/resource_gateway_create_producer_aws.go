// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v2"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceProducerAws() *schema.Resource {
	return &schema.Resource{
		Description: "AWS producer resource",
		Create:      resourceProducerAwsCreate,
		Read:        resourceProducerAwsRead,
		Update:      resourceProducerAwsUpdate,
		Delete:      resourceProducerAwsDelete,
		Importer: &schema.ResourceImporter{
			State: resourceProducerAwsImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Producer name",
			},
			"target_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Name of existing target to use in producer creation",
			},
			"aws_access_key_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Access Key ID",
			},
			"aws_access_secret_key": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Access Secret Key",
			},
			"access_mode": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The types of credentials to retrieve from AWS. Options:[iam_user,assume_role]",
			},
			"region": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Region",
				Default:     "us-east-2",
			},
			"aws_user_policies": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Policy ARN(s). Multiple values should be separated by comma",
			},
			"aws_user_groups": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "UserGroup name(s). Multiple values should be separated by comma",
			},
			"aws_role_arns": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "AWS Role ARNs to be use in the Assume Role operation. Multiple values should be separated by comma",
			},
			"aws_user_console_access": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable AWS User console access",
				Default:     "false",
			},
			"aws_user_programmatic_access": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable AWS User programmatic access",
				Default:     "true",
			},
			"producer_encryption_key_name": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Encrypt producer with following key",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"tags": {
				Type:        schema.TypeSet,
				Required:    false,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_aws_account_id": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "The aws account id",
			},
			"secure_access_aws_native_cli": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "The aws native cli",
			},
			"secure_access_web_browsing": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Secure browser via Akeyless Web Access Bastion",
			},
			"secure_access_bastion_issuer": {
				Type:        schema.TypeString,
				Required:    false,
				Optional:    true,
				Description: "Path to the SSH Certificate Issuer for your Akeyless Bastion",
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Required:    false,
				Optional:    true,
				Description: "Enable Web Secure Remote Access ",
				Default:     "true",
			},
		},
	}
}

func resourceProducerAwsCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
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
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessAwsAccountId := d.Get("secure_access_aws_account_id").(string)
	secureAccessAwsNativeCli := d.Get("secure_access_aws_native_cli").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.GatewayCreateProducerAws{
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
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessAwsAccountId, secureAccessAwsAccountId)
	common.GetAkeylessPtr(&body.SecureAccessAwsNativeCli, secureAccessAwsNativeCli)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.GatewayCreateProducerAws(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerAwsRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()
	body := akeyless.GatewayGetProducer{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GatewayGetProducer(ctx).Body(body).Execute()
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
		err = d.Set("tags", *rOut.Tags)
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
		err = d.Set("producer_encryption_key_name", *rOut.DynamicSecretKey)
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
	if rOut.AwsUserConsoleAccess != nil {
		err = d.Set("aws_user_console_access", *rOut.AwsUserConsoleAccess)
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
	common.GetSra(d, path, token, client)

	d.SetId(path)

	return nil
}

func resourceProducerAwsUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
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
	producerEncryptionKeyName := d.Get("producer_encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessAwsAccountId := d.Get("secure_access_aws_account_id").(string)
	secureAccessAwsNativeCli := d.Get("secure_access_aws_native_cli").(bool)
	secureAccessWebBrowsing := d.Get("secure_access_web_browsing").(bool)
	secureAccessBastionIssuer := d.Get("secure_access_bastion_issuer").(string)
	secureAccessWeb := d.Get("secure_access_web").(bool)

	body := akeyless.GatewayUpdateProducerAws{
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
	common.GetAkeylessPtr(&body.ProducerEncryptionKeyName, producerEncryptionKeyName)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.Tags, tags)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessAwsAccountId, secureAccessAwsAccountId)
	common.GetAkeylessPtr(&body.SecureAccessAwsNativeCli, secureAccessAwsNativeCli)
	common.GetAkeylessPtr(&body.SecureAccessWebBrowsing, secureAccessWebBrowsing)
	common.GetAkeylessPtr(&body.SecureAccessBastionIssuer, secureAccessBastionIssuer)
	common.GetAkeylessPtr(&body.SecureAccessWeb, secureAccessWeb)

	_, _, err := client.GatewayUpdateProducerAws(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceProducerAwsDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.GatewayDeleteProducer{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.GatewayDeleteProducer(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceProducerAwsImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GatewayGetProducer{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GatewayGetProducer(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
