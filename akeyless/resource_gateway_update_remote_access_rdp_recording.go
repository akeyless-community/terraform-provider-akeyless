// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayUpdateRemoteAccessRdpRecording() *schema.Resource {
	return &schema.Resource{
		Description:   "Remote access rdp recording config",
		Create:        resourceGatewayUpdateRemoteAccessRdpRecordingUpdate,
		Read:          resourceGatewayUpdateRemoteAccessRdpRecordingRead,
		Update:        resourceGatewayUpdateRemoteAccessRdpRecordingUpdate,
		DeleteContext: resourceGatewayUpdateRemoteAccessRdpRecordingDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateRemoteAccessRdpRecordingImport,
		},
		Schema: map[string]*schema.Schema{
			"rdp_session_recording": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable recording of rdp session [true/false]",
			},
			"rdp_session_storage": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Rdp session recording storage destination [local/aws/azure]",
			},
			"aws_storage_region": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The region where the storage is located",
			},
			"aws_storage_bucket_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The AWS bucket name. For more information refer to https://docs.aws.amazon.com/s3/",
			},
			"aws_storage_bucket_prefix": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The folder name in S3 bucket. For more information refer to https://docs.aws.amazon.com/s3/",
			},
			"aws_storage_access_key_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "AWS access key id. For more information refer to https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
			},
			"aws_storage_secret_access_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "AWS secret access key. For more information refer to https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html",
			},
			"azure_storage_account_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure account name. For more information refer to https://learn.microsoft.com/en-us/azure/storage/common/storage-account-overview",
			},
			"azure_storage_container_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure container name. For more information refer to https://learn.microsoft.com/en-us/rest/api/storageservices/naming-and-referencing-containers--blobs--and-metadata",
			},
			"azure_storage_client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure client id. For more information refer to https://learn.microsoft.com/en-us/azure/storage/common/storage-account-get-info?tabs=portal",
			},
			"azure_storage_client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Azure client secret. For more information refer to https://learn.microsoft.com/en-us/azure/storage/common/storage-account-get-info?tabs=portal",
			},
			"azure_storage_tenant_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Azure tenant id. For more information refer to https://learn.microsoft.com/en-us/entra/fundamentals/how-to-find-tenant",
			},
		},
	}
}

func resourceGatewayUpdateRemoteAccessRdpRecordingRead(d *schema.ResourceData, m interface{}) error {
	rOut, err := getGwRemoteAccessConfig(m)
	if err != nil {
		return err
	}

	webBastion := rOut.WebBastion
	if webBastion != nil {
		rdpRecord := webBastion.RdpRecord
		if rdpRecord != nil {
			if rdpRecord.StorageType != nil {
				if *rdpRecord.StorageType == "none" {
					err = d.Set("rdp_session_recording", "false")
					if err != nil {
						return err
					}
					err = d.Set("rdp_session_storage", "")
					if err != nil {
						return err
					}
				} else {
					err = d.Set("rdp_session_recording", "true")
					if err != nil {
						return err
					}
					err = d.Set("rdp_session_storage", *rdpRecord.StorageType)
					if err != nil {
						return err
					}
				}
			}
			if rdpRecord.Aws != nil {
				aws := rdpRecord.Aws
				if aws != nil {
					if aws.Region != nil {
						err = d.Set("aws_storage_region", *aws.Region)
						if err != nil {
							return err
						}
					}
					if aws.Bucket != nil {
						err = d.Set("aws_storage_bucket_name", *aws.Bucket)
						if err != nil {
							return err
						}
					}
					if aws.Prefix != nil {
						err = d.Set("aws_storage_bucket_prefix", *aws.Prefix)
						if err != nil {
							return err
						}
					}
					if aws.AccessKeyId != nil {
						err = d.Set("aws_storage_access_key_id", *aws.AccessKeyId)
						if err != nil {
							return err
						}
					}
					if aws.AccessKeySecret != nil {
						err = d.Set("aws_storage_secret_access_key", *aws.AccessKeySecret)
						if err != nil {
							return err
						}
					}
				}
			}
			if rdpRecord.Azure != nil {
				azure := rdpRecord.Azure
				if azure != nil {
					if azure.StorageAccount != nil {
						err = d.Set("azure_storage_account_name", *azure.StorageAccount)
						if err != nil {
							return err
						}
					}
					if azure.StorageContainerName != nil {
						err = d.Set("azure_storage_container_name", *azure.StorageContainerName)
						if err != nil {
							return err
						}
					}
					if azure.ClientId != nil {
						err = d.Set("azure_storage_client_id", *azure.ClientId)
						if err != nil {
							return err
						}
					}
					if azure.ClientSecret != nil {
						err = d.Set("azure_storage_client_secret", *azure.ClientSecret)
						if err != nil {
							return err
						}
					}
					if azure.TenantId != nil {
						err = d.Set("azure_storage_tenant_id", *azure.TenantId)
						if err != nil {
							return err
						}
					}
				}
			}
		}
	}

	d.SetId(*rOut.ClusterId)

	return nil
}

func resourceGatewayUpdateRemoteAccessRdpRecordingUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	rdpSessionRecording := d.Get("rdp_session_recording").(string)
	rdpSessionStorage := d.Get("rdp_session_storage").(string)
	awsStorageRegion := d.Get("aws_storage_region").(string)
	awsStorageBucketName := d.Get("aws_storage_bucket_name").(string)
	awsStorageBucketPrefix := d.Get("aws_storage_bucket_prefix").(string)
	awsStorageAccessKeyId := d.Get("aws_storage_access_key_id").(string)
	awsStorageSecretAccessKey := d.Get("aws_storage_secret_access_key").(string)
	azureStorageAccountName := d.Get("azure_storage_account_name").(string)
	azureStorageContainerName := d.Get("azure_storage_container_name").(string)
	azureStorageClientId := d.Get("azure_storage_client_id").(string)
	azureStorageClientSecret := d.Get("azure_storage_client_secret").(string)
	azureStorageTenantId := d.Get("azure_storage_tenant_id").(string)

	body := akeyless_api.GatewayUpdateRemoteAccessRdpRecordings{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.RdpSessionRecording, rdpSessionRecording)
	common.GetAkeylessPtr(&body.RdpSessionStorage, rdpSessionStorage)
	common.GetAkeylessPtr(&body.AwsStorageRegion, awsStorageRegion)
	common.GetAkeylessPtr(&body.AwsStorageBucketName, awsStorageBucketName)
	common.GetAkeylessPtr(&body.AwsStorageBucketPrefix, awsStorageBucketPrefix)
	common.GetAkeylessPtr(&body.AwsStorageAccessKeyId, awsStorageAccessKeyId)
	common.GetAkeylessPtr(&body.AwsStorageSecretAccessKey, awsStorageSecretAccessKey)
	common.GetAkeylessPtr(&body.AzureStorageAccountName, azureStorageAccountName)
	common.GetAkeylessPtr(&body.AzureStorageContainerName, azureStorageContainerName)
	common.GetAkeylessPtr(&body.AzureStorageClientId, azureStorageClientId)
	common.GetAkeylessPtr(&body.AzureStorageClientSecret, azureStorageClientSecret)
	common.GetAkeylessPtr(&body.AzureStorageTenantId, azureStorageTenantId)

	_, _, err := client.GatewayUpdateRemoteAccessRdpRecordings(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update remote access rdp recording config: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update remote access rdp recording config: %v", err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}
	return nil
}

func resourceGatewayUpdateRemoteAccessRdpRecordingDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateRemoteAccessRdpRecordingImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	err := resourceGatewayUpdateRemoteAccessRdpRecordingRead(d, m)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
