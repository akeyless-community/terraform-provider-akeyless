// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGwSessionForwardingStdout() *schema.Resource {
	return &schema.Resource{
		Description:   "Session Forwarding config for standard output",
		Create:        resourceGwSessionForwardingStdoutUpdate,
		Read:          resourceGwSessionForwardingStdoutRead,
		Update:        resourceGwSessionForwardingStdoutUpdate,
		DeleteContext: resourceGwSessionForwardingStdoutDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGwSessionForwardingStdoutImport,
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
		},
	}
}

func resourceGwSessionForwardingStdoutRead(d *schema.ResourceData, m interface{}) error {

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

	return nil
}

func resourceGwSessionForwardingStdoutUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	enable := d.Get("enable").(string)
	outputFormat := d.Get("output_format").(string)
	pullInterval := d.Get("pull_interval").(string)

	body := akeyless_api.GwUpdateRemoteAccessSessionLogsStdout{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Enable, enable)
	common.GetAkeylessPtr(&body.OutputFormat, outputFormat)
	common.GetAkeylessPtr(&body.PullInterval, pullInterval)

	_, resp, err := client.GwUpdateRemoteAccessSessionLogsStdout(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update session forwarding settings", resp, err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGwSessionForwardingStdoutDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGwSessionForwardingStdoutImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	err := resourceGwSessionForwardingStdoutRead(d, m)
	if err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}

func getGwRemoteAccessSessionLogsConfig(m interface{}) (*akeyless_api.LogForwardingConfigPart, error) {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	body := akeyless_api.GatewayGetRemoteAccess{
		Token: &token,
	}

	rOut, resp, err := client.GatewayGetRemoteAccess(ctx).Body(body).Execute()
	if err != nil {
		return nil, common.HandleError("can't get remote access session logs config", resp, err)
	}

	if rOut.SshBastion != nil && rOut.SshBastion.LogForwarding != nil {
		return rOut.SshBastion.LogForwarding, nil
	}

	return akeyless_api.NewLogForwardingConfigPart(), nil
}
