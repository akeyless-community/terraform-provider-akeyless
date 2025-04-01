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

func resourceGatewayUpdateCache() *schema.Resource {
	return &schema.Resource{
		Description:   "Cache settings",
		Create:        resourceGatewayUpdateCacheUpdate,
		Read:          resourceGatewayUpdateCacheRead,
		Update:        resourceGatewayUpdateCacheUpdate,
		DeleteContext: resourceGatewayUpdateCacheDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayUpdateCacheImport,
		},
		Schema: map[string]*schema.Schema{
			"enable_cache": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable cache [true/false]",
				Default:     "false",
			},
			"stale_timeout": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Stale timeout in minutes, cache entries which are not accessed within timeout will be removed from cache",
				Default:     "60",
			},
			"enable_proactive": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable proactive caching [true/false]",
				Default:     "false",
			},
			"minimum_fetch_interval": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "When using Cache or/and Proactive Cache, additional secrets will be fetched upon requesting a secret, based on the requestor's access policy. Define minimum fetching interval to avoid over fetching in a given time frame",
				Default:     "5",
			},
			"backup_interval": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Secure backup interval in minutes. To ensure service continuity in case of power cycle and network outage secrets will be backed up periodically per backup interval",
				Default:     "1",
			},
		},
	}
}

func resourceGatewayUpdateCacheRead(d *schema.ResourceData, m interface{}) error {

	rOut, err := getGwCacheConfig(m)
	if err != nil {
		return err
	}

	if rOut.CacheEnable != nil {
		err := d.Set("enable_cache", strconv.FormatBool(*rOut.CacheEnable))
		if err != nil {
			return err
		}
	}
	if rOut.CacheTtl != nil {
		err := d.Set("stale_timeout", *rOut.CacheTtl)
		if err != nil {
			return err
		}
	}
	if rOut.ProactiveCacheEnable != nil {
		err := d.Set("enable_proactive", strconv.FormatBool(*rOut.ProactiveCacheEnable))
		if err != nil {
			return err
		}
	}
	if rOut.ProactiveCacheMinimumFetchingTime != nil {
		err := d.Set("minimum_fetch_interval", *rOut.ProactiveCacheMinimumFetchingTime)
		if err != nil {
			return err
		}
	}
	if rOut.ProactiveCacheDumpInterval != nil {
		err := d.Set("backup_interval", *rOut.ProactiveCacheDumpInterval)
		if err != nil {
			return err
		}
	}

	return nil
}

func resourceGatewayUpdateCacheUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	enableCache := d.Get("enable_cache").(string)
	staleTimeout := d.Get("stale_timeout").(string)
	enableProactive := d.Get("enable_proactive").(string)
	minimumFetchInterval := d.Get("minimum_fetch_interval").(string)
	backupInterval := d.Get("backup_interval").(string)

	body := akeyless_api.GatewayUpdateCache{
		Token: &token,
	}
	common.GetAkeylessPtr(&body.EnableCache, enableCache)
	common.GetAkeylessPtr(&body.StaleTimeout, staleTimeout)
	common.GetAkeylessPtr(&body.EnableProactive, enableProactive)
	common.GetAkeylessPtr(&body.MinimumFetchInterval, minimumFetchInterval)
	common.GetAkeylessPtr(&body.BackupInterval, backupInterval)

	_, _, err := client.GatewayUpdateCache(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update cache settings: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update cache settings: %v", err)
	}

	if d.Id() == "" {
		id := uuid.New().String()
		d.SetId(id)
	}

	return nil
}

func resourceGatewayUpdateCacheDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {

	return diag.Diagnostics{common.WarningDiagnostics("Destroying the Gateway configuration is not supported. To make changes, please update the configuration explicitly using the update endpoint or delete the Gateway cluster manually.")}
}

func resourceGatewayUpdateCacheImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	rOut, err := getGwCacheConfig(m)
	if err != nil {
		return nil, err
	}

	if rOut.CacheEnable != nil {
		err := d.Set("enable_cache", strconv.FormatBool(*rOut.CacheEnable))
		if err != nil {
			return nil, err
		}
	}
	if rOut.CacheTtl != nil {
		err := d.Set("stale_timeout", *rOut.CacheTtl)
		if err != nil {
			return nil, err
		}
	}
	if rOut.ProactiveCacheEnable != nil {
		err := d.Set("enable_proactive", strconv.FormatBool(*rOut.ProactiveCacheEnable))
		if err != nil {
			return nil, err
		}
	}
	if rOut.ProactiveCacheMinimumFetchingTime != nil {
		err := d.Set("minimum_fetch_interval", *rOut.ProactiveCacheMinimumFetchingTime)
		if err != nil {
			return nil, err
		}
	}
	if rOut.ProactiveCacheDumpInterval != nil {
		err := d.Set("backup_interval", *rOut.ProactiveCacheDumpInterval)
		if err != nil {
			return nil, err
		}
	}

	return []*schema.ResourceData{d}, nil
}

func getGwCacheConfig(m interface{}) (*akeyless_api.CacheConfigPart, error) {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	body := akeyless_api.GatewayGetCache{
		Token: &token,
	}

	rOut, _, err := client.GatewayGetCache(ctx).Body(body).Execute()
	if err != nil {
		var apiErr akeyless_api.GenericOpenAPIError
		if errors.As(err, &apiErr) {
			return &akeyless_api.CacheConfigPart{}, fmt.Errorf("can't get cache settings: %v", string(apiErr.Body()))
		}
		return &akeyless_api.CacheConfigPart{}, fmt.Errorf("can't get cache settings: %w", err)
	}

	return rOut, nil
}
