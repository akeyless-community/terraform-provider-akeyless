// generated file
package akeyless

import (
	"context"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceLinkedTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Linked Target resource",
		Create:      resourceLinkedTargetCreate,
		Read:        resourceLinkedTargetRead,
		Update:      resourceLinkedTargetUpdate,
		Delete:      resourceLinkedTargetDelete,
		Importer: &schema.ResourceImporter{
			State: resourceLinkedTargetImport,
		},
		Schema: map[string]*schema.Schema{
			"lock_on_read":     {Type: schema.TypeString, Optional: true, Description: "Lock after read"},
			"lock_ttl":         {Type: schema.TypeString, Optional: true, Description: "Lock TTL in minutes"},
			"rotate_on_unlock": {Type: schema.TypeString, Optional: true, Description: "Rotate after unlock"},

			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Linked Target name",
				ForceNew:    true,
			},
			"hosts": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma seperated list of server hosts and server descriptions joined by semicolon ';' (i.e. 'server-dev.com;My Dev server,server-prod.com;My Prod server description')",
			},
			"parent_target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The parent Target name",
			},
			"type": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Specifies the hosts type, relevant only when working without parent target",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description of the object",
			},
			"add_hosts": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "A comma seperated list of new server hosts and server descriptions joined by semicolon ';' that will be added to the Linked Target hosts.",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Whether to keep previous version [true/false]. If not set, use default according to account settings",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Set the maximum number of versions, limited by the account settings defaults",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "false",
				Description: "Protection from accidental deletion of this object [true/false]",
			},
			"rm_hosts": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Comma separated list of existing hosts that will be removed from Linked Target hosts.",
			},
		},
	}
}

func resourceLinkedTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	hosts := d.Get("hosts").(string)
	parentTargetName := d.Get("parent_target_name").(string)
	hostType := d.Get("type").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetCreateLinked{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Hosts, hosts)
	common.GetAkeylessPtr(&body.ParentTargetName, parentTargetName)
	common.GetAkeylessPtr(&body.Type, hostType)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))

	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))

	_, resp, err := client.TargetCreateLinked(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create Target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceLinkedTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get target details", res, err)
	}

	if rOut.Value.LinkedTargetDetails.Hosts != nil {
		err = d.Set("hosts", getLinkedHosts(d.Get("hosts").(string), *rOut.Value.LinkedTargetDetails.Hosts))
		if err != nil {
			return err
		}
	}
	if rOut.Target.TargetItemsAssoc != nil {
		if (rOut.Target.TargetItemsAssoc)[0].ItemName != nil {
			err = d.Set("parent_target_name", *rOut.Target.TargetItemsAssoc[0].ItemName)
			if err != nil {
				return err
			}
		}
	}
	if rOut.Target.Attributes != nil {
		if hostType, ok := (rOut.Target.Attributes)["parent_target_type"]; ok {
			err = d.Set("type", fmt.Sprintf("%v", hostType))
			if err != nil {
				return err
			}
		}
	}
	if rOut.Target.Comment != nil {
		err = d.Set("description", *rOut.Target.Comment)
		if err != nil {
			return err
		}
	}
	if rOut.Target.DeleteProtection != nil {
		err = d.Set("delete_protection", strconv.FormatBool(*rOut.Target.DeleteProtection))
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func getLinkedHosts(currentHosts string, hosts map[string]string) string {
	currentHostsMap := convertHostStringToMap(currentHosts)
	if reflect.DeepEqual(currentHostsMap, hosts) {
		return currentHosts
	}

	return convertHostsMapToString(hosts)
}

func convertHostStringToMap(hostsStr string) map[string]string {
	hostsMap := make(map[string]string)
	hostsArr := strings.Split(hostsStr, ",")
	for _, hostDesc := range hostsArr {
		hostDescArr := strings.SplitN(hostDesc, ";", 2)
		if len(hostDescArr) == 2 {
			hostsMap[hostDescArr[0]] = hostDescArr[1]
		} else {
			hostsMap[hostDescArr[0]] = ""
		}
	}
	return hostsMap
}

func convertHostsMapToString(hosts map[string]string) string {
	var hostsStr string
	for host, desc := range hosts {
		hostsStr += host + ";" + desc + ","
	}
	hostsStr = strings.TrimSuffix(hostsStr, ",")

	return hostsStr
}

func resourceLinkedTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	hosts := d.Get("hosts").(string)
	parentTargetName := d.Get("parent_target_name").(string)
	hostType := d.Get("type").(string)
	description := d.Get("description").(string)
	addHosts := d.Get("add_hosts").(string)
	keepPrevVersion := d.Get("keep_prev_version").(string)
	rmHosts := d.Get("rm_hosts").(string)

	body := akeyless_api.TargetUpdateLinked{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Hosts, hosts)
	common.GetAkeylessPtr(&body.ParentTargetName, parentTargetName)
	common.GetAkeylessPtr(&body.Type, hostType)
	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.AddHosts, addHosts)
	common.GetAkeylessPtr(&body.KeepPrevVersion, keepPrevVersion)
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))
	common.GetAkeylessPtr(&body.RmHosts, rmHosts)

	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))

	_, resp, err := client.TargetUpdateLinked(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceLinkedTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.TargetDelete{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.TargetDelete(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceLinkedTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	id := d.Id()

	err := resourceLinkedTargetRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
