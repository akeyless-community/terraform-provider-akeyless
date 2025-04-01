// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
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
		},
	}
}

func resourceLinkedTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
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

	_, _, err := client.TargetCreateLinked(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Target: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Target: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceLinkedTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.TargetGetDetails{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.TargetGetDetails(ctx).Body(body).Execute()
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

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	hosts := d.Get("hosts").(string)
	parentTargetName := d.Get("parent_target_name").(string)
	hostType := d.Get("type").(string)
	description := d.Get("description").(string)

	body := akeyless_api.TargetUpdateLinked{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.Hosts, hosts)
	common.GetAkeylessPtr(&body.ParentTargetName, parentTargetName)
	common.GetAkeylessPtr(&body.Type, hostType)
	common.GetAkeylessPtr(&body.Description, description)

	_, _, err := client.TargetUpdateLinked(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
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
