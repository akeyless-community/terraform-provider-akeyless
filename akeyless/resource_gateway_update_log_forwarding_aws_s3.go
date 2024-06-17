// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v4"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayUpdateLogForwardingAwsS3() *schema.Resource {
	return &schema.Resource{
		Description: "Log Forwarding config for aws-s3",
		Create:      resourceGatewayUpdateLogForwardingAwsS3Update,
		Read:        resourceGatewayUpdateLogForwardingAwsS3Read,
		Update:      resourceGatewayUpdateLogForwardingAwsS3Update,
		Delete:      resourceGatewayUpdateLogForwardingAwsS3Update,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateLogForwardingAwsS3Import,
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

func resourceGatewayUpdateLogForwardingAwsS3Read(d *schema.ResourceData, m interface{}) error {

	rOut, err := getGwLogForwardingConfig(m)
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
		if config.LogFolder != nil && d.Get("log_folder").(string) != common.UseExisting {
			err := d.Set("log_folder", *config.LogFolder)
			if err != nil {
				return err
			}
		}
		if config.BucketName != nil && d.Get("bucket_name") != "" {
			err := d.Set("bucket_name", *config.BucketName)
			if err != nil {
				return err
			}
		}
		if config.AwsAuthType != nil && d.Get("auth_type") != "" {
			err := d.Set("auth_type", adjustLogForwardingAwsS3AuthType(*config.AwsAuthType))
			if err != nil {
				return err
			}
		}
		if config.AwsAccessId != nil && d.Get("access_id") != "" {
			err := d.Set("access_id", *config.AwsAccessId)
			if err != nil {
				return err
			}
		}
		if config.AwsAccessKey != nil && d.Get("access_key") != "" {
			err := d.Set("access_key", *config.AwsAccessKey)
			if err != nil {
				return err
			}
		}
		if config.AwsRegion != nil && d.Get("region") != "" {
			err := d.Set("region", *config.AwsRegion)
			if err != nil {
				return err
			}
		}
		if config.AwsRoleArn != nil && d.Get("role_arn") != "" {
			err = d.Set("role_arn", *config.AwsRoleArn)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGatewayUpdateLogForwardingAwsS3Update(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	logFolder := d.Get("log_folder").(string)
	bucketName := d.Get("bucket_name").(string)
	authType := d.Get("auth_type").(string)
	accessId := d.Get("access_id").(string)
	accessKey := d.Get("access_key").(string)
	region := d.Get("region").(string)
	roleArn := d.Get("role_arn").(string)

	body := akeyless_api.GatewayUpdateLogForwardingAwsS3{
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

	_, _, err := client.GatewayUpdateLogForwardingAwsS3(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update log forwarding settings: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update log forwarding settings: %v", err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGatewayUpdateLogForwardingAwsS3Import(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	rOut, err := getGwLogForwardingConfig(m)
	if err != nil {
		return nil, err
	}

	if rOut.LoganEnable != nil {
		err := d.Set("enable", strconv.FormatBool(*rOut.LoganEnable))
		if err != nil {
			return nil, err
		}
	}
	if rOut.JsonOutput != nil {
		err := d.Set("output_format", common.ExtractLogForwardingFormat(*rOut.JsonOutput))
		if err != nil {
			return nil, err
		}
	}
	if rOut.PullIntervalSec != nil {
		err := d.Set("pull_interval", *rOut.PullIntervalSec)
		if err != nil {
			return nil, err
		}
	}

	config := rOut.AwsS3Config
	if config != nil {
		if config.LogFolder != nil {
			err := d.Set("log_folder", *config.LogFolder)
			if err != nil {
				return nil, err
			}
		}
		if config.BucketName != nil {
			err := d.Set("bucket_name", *config.BucketName)
			if err != nil {
				return nil, err
			}
		}
		if config.AwsAuthType != nil {
			err := d.Set("auth_type", adjustLogForwardingAwsS3AuthType(*config.AwsAuthType))
			if err != nil {
				return nil, err
			}
		}
		if config.AwsAccessId != nil {
			err := d.Set("access_id", *config.AwsAccessId)
			if err != nil {
				return nil, err
			}
		}
		if config.AwsAccessKey != nil {
			err := d.Set("access_key", *config.AwsAccessKey)
			if err != nil {
				return nil, err
			}
		}
		if config.AwsRegion != nil {
			err := d.Set("region", *config.AwsRegion)
			if err != nil {
				return nil, err
			}
		}
		if config.AwsRoleArn != nil {
			err = d.Set("role_arn", *config.AwsRoleArn)
			if err != nil {
				return nil, err
			}
		}
	}

	return []*schema.ResourceData{d}, nil
}

func adjustLogForwardingAwsS3AuthType(authType string) string {
	switch authType {
	case "aws_auth_type_access_key":
		return "access_key"
	case "aws_auth_type_cloud_id":
		return "cloud_id"
	case "aws_auth_type_assume_role":
		return "assume_role"
	default:
		return string(authType)
	}
}
