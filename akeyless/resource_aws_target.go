package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAwsTarget() *schema.Resource {
	return &schema.Resource{
		Description: "AWS Target resource",
		Create:      resourceAwsTargetCreate,
		Read:        resourceAwsTargetRead,
		Update:      resourceAwsTargetUpdate,
		Delete:      resourceAwsTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAwsTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target name",
				ForceNew:    true,
			},
			"access_key_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "AWS access key ID",
			},
			"access_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS secret access key",
			},
			"session_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Required only for temporary security credentials retrieved using STS",
			},
			"region": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS region",
				Default:     "us-east-2",
			},
			"use_gw_cloud_identity": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Use the GW's Cloud IAM",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Key name. The key will be used to encrypt the target secret value. If key name is not specified, the account default protection key is used",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
		},
	}
}

func resourceAwsTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	accessKeyId := d.Get("access_key_id").(string)
	accessKey := d.Get("access_key").(string)
	sessionToken := d.Get("session_token").(string)
	region := d.Get("region").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	key := d.Get("key").(string)
	description := d.Get("description").(string)

	body := akeyless.CreateAWSTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.AccessKeyId, accessKeyId)
	common.GetAkeylessPtr(&body.AccessKey, accessKey)
	common.GetAkeylessPtr(&body.SessionToken, sessionToken)
	common.GetAkeylessPtr(&body.Region, region)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.Key, key)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.CreateAWSTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAwsTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	path := d.Id()

	body := akeyless.GetTargetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GetTargetDetails(ctx).Body(body).Execute()
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
	if rOut.Value == nil || rOut.Target == nil {
		return fmt.Errorf("can't get value")
	}

	if rOut.Value.AwsTargetDetails.AwsAccessKeyId != nil {
		err = d.Set("access_key_id", *rOut.Value.AwsTargetDetails.AwsAccessKeyId)
		if err != nil {
			return err
		}
	}
	if rOut.Target.ProtectionKeyName != nil {
		err = d.Set("key", *rOut.Target.ProtectionKeyName)
		if err != nil {
			return err
		}
	}
	if rOut.Target.Comment != nil {
		err := d.Set("description", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}

	if rOut.Value.AwsTargetDetails.AwsSecretAccessKey != nil {
		err = d.Set("access_key", *rOut.Value.AwsTargetDetails.AwsSecretAccessKey)
		if err != nil {
			return err
		}
	}
	if rOut.Value.AwsTargetDetails.AwsSessionToken != nil {
		err = d.Set("session_token", *rOut.Value.AwsTargetDetails.AwsSessionToken)
		if err != nil {
			return err
		}
	}
	if rOut.Value.AwsTargetDetails.AwsRegion != nil {
		err = d.Set("region", *rOut.Value.AwsTargetDetails.AwsRegion)
		if err != nil {
			return err
		}
	}
	if rOut.Value.AwsTargetDetails.UseGwCloudIdentity != nil {
		err = d.Set("use_gw_cloud_identity", *rOut.Value.AwsTargetDetails.UseGwCloudIdentity)
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceAwsTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	accessKeyId := d.Get("access_key_id").(string)
	accessKey := d.Get("access_key").(string)
	sessionToken := d.Get("session_token").(string)
	region := d.Get("region").(string)
	useGwCloudIdentity := d.Get("use_gw_cloud_identity").(bool)
	key := d.Get("key").(string)

	body := akeyless.UpdateAWSTarget{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.AccessKeyId, accessKeyId)
	common.GetAkeylessPtr(&body.AccessKey, accessKey)
	common.GetAkeylessPtr(&body.SessionToken, sessionToken)
	common.GetAkeylessPtr(&body.Region, region)
	common.GetAkeylessPtr(&body.UseGwCloudIdentity, useGwCloudIdentity)
	common.GetAkeylessPtr(&body.Key, key)

	_, _, err := client.UpdateAWSTarget(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAwsTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.DeleteTarget{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.DeleteTarget(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceAwsTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceAwsTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
