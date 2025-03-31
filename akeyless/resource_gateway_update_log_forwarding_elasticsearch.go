// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayUpdateLogForwardingElasticsearch() *schema.Resource {
	return &schema.Resource{
		Description:   "Log Forwarding config for elasticsearch",
		Create:        resourceGatewayUpdateLogForwardingElasticsearchUpdate,
		Read:          resourceGatewayUpdateLogForwardingElasticsearchRead,
		Update:        resourceGatewayUpdateLogForwardingElasticsearchUpdate,
		DeleteContext: resourceGatewayUpdateLogForwardingElasticsearchDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateLogForwardingElasticsearchImport,
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
			"index": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Elasticsearch index",
			},
			"server_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Elasticsearch server type [nodes/cloud]",
			},
			"nodes": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Elasticsearch nodes relevant only for nodes server-type",
			},
			"cloud_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Elasticsearch cloud id relevant only for cloud server-type",
			},
			"auth_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Elasticsearch auth type [api_key/password]",
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Elasticsearch api key relevant only for api_key auth-type",
			},
			"user_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Elasticsearch user name relevant only for password auth-type",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Elasticsearch password relevant only for password auth-type",
			},
			"enable_tls": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable tls",
			},
			"tls_certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Elasticsearch tls certificate (PEM format) in a Base64 format",
				Default:     "use-existing",
			},
		},
	}
}

func resourceGatewayUpdateLogForwardingElasticsearchRead(d *schema.ResourceData, m interface{}) error {

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

	config := rOut.ElasticsearchConfig
	if config != nil {
		if config.ElasticsearchIndex != nil && d.Get("index").(string) != "" {
			err := d.Set("index", *config.ElasticsearchIndex)
			if err != nil {
				return err
			}
		}
		if config.ElasticsearchServerType != nil && d.Get("server_type").(string) != "" {
			err := d.Set("server_type", adjustElasticsearchServerType(*config.ElasticsearchServerType))
			if err != nil {
				return err
			}
		}
		if config.ElasticsearchNodes != nil && d.Get("nodes").(string) != "" {
			err := d.Set("nodes", *config.ElasticsearchNodes)
			if err != nil {
				return err
			}
		}
		if config.ElasticsearchCloudId != nil && d.Get("cloud_id").(string) != "" {
			err := d.Set("cloud_id", *config.ElasticsearchCloudId)
			if err != nil {
				return err
			}
		}
		if config.ElasticsearchAuthType != nil && d.Get("auth_type").(string) != "" {
			err := d.Set("auth_type", adjustElasticsearchAuthType(*config.ElasticsearchAuthType))
			if err != nil {
				return err
			}
		}
		if config.ElasticsearchApiKey != nil && d.Get("api_key").(string) != "" {
			err := d.Set("api_key", *config.ElasticsearchApiKey)
			if err != nil {
				return err
			}
		}
		if config.ElasticsearchUserName != nil && d.Get("user_name").(string) != "" {
			err := d.Set("user_name", *config.ElasticsearchUserName)
			if err != nil {
				return err
			}
		}
		if config.ElasticsearchPassword != nil && d.Get("password").(string) != "" {
			err := d.Set("password", *config.ElasticsearchPassword)
			if err != nil {
				return err
			}
		}
		if config.ElasticsearchEnableTls != nil {
			err := d.Set("enable_tls", *config.ElasticsearchEnableTls)
			if err != nil {
				return err
			}
		}
		if config.ElasticsearchTlsCertificate != nil && d.Get("tls_certificate").(string) != common.UseExisting {
			err := d.Set("tls_certificate", common.Base64Encode(*config.ElasticsearchTlsCertificate))
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func resourceGatewayUpdateLogForwardingElasticsearchUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)
	index := d.Get("index").(string)
	serverType := d.Get("server_type").(string)
	nodes := d.Get("nodes").(string)
	cloudId := d.Get("cloud_id").(string)
	authType := d.Get("auth_type").(string)
	apiKey := d.Get("api_key").(string)
	userName := d.Get("user_name").(string)
	password := d.Get("password").(string)
	enableTls := d.Get("enable_tls").(bool)
	tlsCertificate := d.Get("tls_certificate").(string)

	body := akeyless_api.GatewayUpdateLogForwardingElasticsearch{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)
	common.GetAkeylessPtr(&body.Index, index)
	common.GetAkeylessPtr(&body.ServerType, serverType)
	common.GetAkeylessPtr(&body.Nodes, nodes)
	common.GetAkeylessPtr(&body.CloudId, cloudId)
	common.GetAkeylessPtr(&body.AuthType, authType)
	common.GetAkeylessPtr(&body.ApiKey, apiKey)
	common.GetAkeylessPtr(&body.UserName, userName)
	common.GetAkeylessPtr(&body.Password, password)
	common.GetAkeylessPtr(&body.EnableTls, enableTls)
	common.GetAkeylessPtr(&body.TlsCertificate, tlsCertificate)

	_, _, err := client.GatewayUpdateLogForwardingElasticsearch(ctx).Body(body).Execute()
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

func resourceGatewayUpdateLogForwardingElasticsearchDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateLogForwardingElasticsearchImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

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

	config := rOut.ElasticsearchConfig
	if config != nil {
		if config.ElasticsearchIndex != nil {
			err := d.Set("index", *config.ElasticsearchIndex)
			if err != nil {
				return nil, err
			}
		}
		if config.ElasticsearchServerType != nil {
			err := d.Set("server_type", adjustElasticsearchServerType(*config.ElasticsearchServerType))
			if err != nil {
				return nil, err
			}
		}
		if config.ElasticsearchNodes != nil {
			err := d.Set("nodes", *config.ElasticsearchNodes)
			if err != nil {
				return nil, err
			}
		}
		if config.ElasticsearchCloudId != nil {
			err := d.Set("cloud_id", *config.ElasticsearchCloudId)
			if err != nil {
				return nil, err
			}
		}
		if config.ElasticsearchAuthType != nil {
			err := d.Set("auth_type", adjustElasticsearchAuthType(*config.ElasticsearchAuthType))
			if err != nil {
				return nil, err
			}
		}
		if config.ElasticsearchApiKey != nil {
			err := d.Set("api_key", *config.ElasticsearchApiKey)
			if err != nil {
				return nil, err
			}
		}
		if config.ElasticsearchUserName != nil {
			err := d.Set("user_name", *config.ElasticsearchUserName)
			if err != nil {
				return nil, err
			}
		}
		if config.ElasticsearchPassword != nil {
			err := d.Set("password", *config.ElasticsearchPassword)
			if err != nil {
				return nil, err
			}
		}
		if config.ElasticsearchEnableTls != nil {
			err := d.Set("enable_tls", *config.ElasticsearchEnableTls)
			if err != nil {
				return nil, err
			}
		}
		if config.ElasticsearchTlsCertificate != nil {
			err := d.Set("tls_certificate", common.Base64Encode(*config.ElasticsearchTlsCertificate))
			if err != nil {
				return nil, err
			}
		}
	}

	return []*schema.ResourceData{d}, nil
}

func adjustElasticsearchServerType(serverType string) string {
	switch serverType {
	case "elastic-server-nodes":
		return "nodes"
	case "elastic-server-cloudId":
		return "cloud_id"
	default:
		return serverType
	}
}

func adjustElasticsearchAuthType(authType string) string {
	switch authType {
	case "elastic-auth-apiKey":
		return "api_key"
	case "elastic-auth-usrPwd":
		return "password"
	default:
		return authType
	}
}
