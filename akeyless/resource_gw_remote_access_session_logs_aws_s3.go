// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceGwSessionForwardingAwsS3() *schema.Resource {
	return &schema.Resource{
		Description:   "Session Forwarding config for aws-s3",
		Create:        resourceGwSessionForwardingAwsS3Update,
		Read:          resourceGwSessionForwardingAwsS3Read,
		Update:        resourceGwSessionForwardingAwsS3Update,
		DeleteContext: resourceGwSessionForwardingAwsS3Delete,
		Importer: &schema.ResourceImporter{
			State: resourceGwSessionForwardingAwsS3Import,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("access_key"), cty.GetAttrPath("access_key_wo")),
		},
		Schema: map[string]*schema.Schema{
			"enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable Log Forwarding [true/false]",
				Default:     "true",
			},
			"output_format": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Logs format [text/json]",
				Default:     "text",
			},
			"pull_interval": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Pull interval in seconds",
				Default:     "10",
			},
			"log_folder": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS S3 destination folder for logs",
				Default:     "use-existing",
			},
			"bucket_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS S3 bucket name",
			},
			"auth_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS auth type [access_key/cloud_id/assume_role]",
			},
			"access_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS access id relevant for access_key auth-type",
			},
			"access_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "AWS access key relevant for access_key auth-type",
			},
			"access_key_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "AWS access key relevant for access_key auth-type (write-only, not stored in state). Requires Terraform 1.11+. Bump access_key_wo_version to change it.",
			},
			"access_key_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for access_key_wo. Increment to update the value.",
			},
			"region": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS region",
			},
			"role_arn": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS role arn relevant for assume_role auth-type",
			},
		},
	}
}

func resourceGwSessionForwardingAwsS3Read(d *schema.ResourceData, m interface{}) error {

	rOut, err := getGwRemoteAccessSessionLogsConfig(m)
	if err != nil {
		return err
	}

	if rOut.LoganEnable != nil {
		err := d.Set("enable", strconv.FormatBool(*rOut.LoganEnable))
		if err != nil {
			return err
		}
	}
	if rOut.JsonOutput != nil {
		err := d.Set("output_format", common.ExtractLogForwardingFormat(*rOut.JsonOutput))
		if err != nil {
			return err
		}
	}
	if rOut.PullIntervalSec != nil {
		err := d.Set("pull_interval", *rOut.PullIntervalSec)
		if err != nil {
			return err
		}
	}

	config := rOut.AwsS3Config
	if config != nil {
		if config.LogFolder != nil {
			err := d.Set("log_folder", *config.LogFolder)
			if err != nil {
				return err
			}
		}
		if config.BucketName != nil {
			err := d.Set("bucket_name", *config.BucketName)
			if err != nil {
				return err
			}
		}
		if config.AwsAuthType != nil {
			err := d.Set("auth_type", adjustLogForwardingAwsS3AuthType(*config.AwsAuthType))
			if err != nil {
				return err
			}
		}
		if config.AwsAccessId != nil {
			err := d.Set("access_id", *config.AwsAccessId)
			if err != nil {
				return err
			}
		}
		if config.AwsAccessKey != nil {
			err := common.SetSecretFromRead(d, "access_key", "access_key_wo", "access_key_wo_version", *config.AwsAccessKey)
			if err != nil {
				return err
			}
		}
		if config.AwsRegion != nil {
			err := d.Set("region", *config.AwsRegion)
			if err != nil {
				return err
			}
		}
		if config.AwsRoleArn != nil {
			err := d.Set("role_arn", *config.AwsRoleArn)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGwSessionForwardingAwsS3Update(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	logFolder := d.Get("log_folder").(string)
	bucketName := d.Get("bucket_name").(string)
	authType := d.Get("auth_type").(string)
	accessId := d.Get("access_id").(string)
	accessKey, err := common.EffectiveSecretValue(d, "access_key", "access_key_wo")
	if err != nil {
		return err
	}
	region := d.Get("region").(string)
	roleArn := d.Get("role_arn").(string)

	body := akeyless_api.GwUpdateRemoteAccessSessionLogsAwsS3{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.LogFolder, logFolder)
	common.GetAkeylessPtr(&body.BucketName, bucketName)
	common.GetAkeylessPtr(&body.AuthType, authType)
	common.GetAkeylessPtr(&body.AccessId, accessId)
	common.GetAkeylessPtr(&body.AccessKey, accessKey)
	common.GetAkeylessPtr(&body.Region, region)
	common.GetAkeylessPtr(&body.RoleArn, roleArn)

	_, resp, err := client.GwUpdateRemoteAccessSessionLogsAwsS3(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update session forwarding settings", resp, err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGwSessionForwardingAwsS3Delete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGwSessionForwardingAwsS3Import(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	err := resourceGwSessionForwardingAwsS3Read(d, m)
	if err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
