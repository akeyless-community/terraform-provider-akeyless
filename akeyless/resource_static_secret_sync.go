// generated file
package akeyless

import (
	"context"
	"fmt"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceStaticSecretSync() *schema.Resource {
	return &schema.Resource{
		Description: "Sync Static Secret with Universal Secrets Connector resource",
		Create:      resourceStaticSecretSyncCreate,
		Read:        resourceStaticSecretSyncRead,
		Update:      resourceStaticSecretSyncUpdate,
		Delete:      resourceStaticSecretSyncDelete,
		Importer: &schema.ResourceImporter{
			State: resourceStaticSecretSyncImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Static Secret name",
				ForceNew:    true,
			},
			"usc_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Universal Secret Connector name",
				ForceNew:    true,
			},
			"remote_secret_name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Remote Secret Name that will be synced on the remote endpoint",
				ForceNew:    true,
			},
			"namespace": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Vault namespace, releavnt only for Hashicorp Vault Target",
			},
			"filter_secret_value": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "JQ expression to filter or transform the secret value",
			},
		},
	}
}

func resourceStaticSecretSyncCreate(d *schema.ResourceData, m any) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	secretName := d.Get("name").(string)
	uscName := d.Get("usc_name").(string)
	remoteSecretName := d.Get("remote_secret_name").(string)
	namespace := d.Get("namespace").(string)
	filterSecretValue := d.Get("filter_secret_value").(string)

	body := akeyless_api.StaticSecretSync{
		Name:  secretName,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.UscName, uscName)
	common.GetAkeylessPtr(&body.RemoteSecretName, remoteSecretName)
	common.GetAkeylessPtr(&body.Namespace, namespace)
	common.GetAkeylessPtr(&body.FilterSecretValue, filterSecretValue)

	_, resp, err := client.StaticSecretSync(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't sync static secret", resp, err)
	}

	d.SetId(buildStaticUscSyncId(secretName, uscName, remoteSecretName))

	return nil
}

func resourceStaticSecretSyncRead(d *schema.ResourceData, m any) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	secretName, uscName, remoteSecretName, err := extractStaticUscSyncFromId(d.Id())
	if err != nil {
		return err
	}

	body := akeyless_api.DescribeItem{
		Name:  secretName,
		Token: &token,
	}

	rOut, resp, err := client.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get usc", resp, err)
	}

	if rOut.UscSyncAssociatedItems != nil {
		namespace, filterSecretValue, exists := common.GetRotatorUscSync(rOut.UscSyncAssociatedItems, uscName, remoteSecretName)
		if !exists {
			return fmt.Errorf("static secret sync not found for secret name: %s, usc name: %s, remote secret name: %s", secretName, uscName, remoteSecretName)
		}
		err = d.Set("namespace", namespace)
		if err != nil {
			return err
		}
		err = d.Set("filter_secret_value", filterSecretValue)
		if err != nil {
			return err
		}
	}

	d.SetId(buildStaticUscSyncId(secretName, uscName, remoteSecretName))

	return nil
}

func resourceStaticSecretSyncUpdate(d *schema.ResourceData, m any) error {
	return nil
}

func resourceStaticSecretSyncDelete(d *schema.ResourceData, m any) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	secretName, uscName, _, err := extractStaticUscSyncFromId(d.Id())
	if err != nil {
		return err
	}

	deleteItem := akeyless_api.StaticSecretDeleteSync{
		Token:   &token,
		Name:    secretName,
		UscName: uscName,
	}

	_, _, err = client.StaticSecretDeleteSync(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceStaticSecretSyncImport(d *schema.ResourceData, m any) ([]*schema.ResourceData, error) {

	ctx := context.Background()

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	secretName, uscName, remoteSecretName, err := extractStaticUscSyncFromId(d.Id())
	if err != nil {
		return nil, err
	}

	body := akeyless_api.DescribeItem{
		Name:  secretName,
		Token: &token,
	}

	rOut, resp, err := client.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		return nil, common.HandleReadError(d, "can't get usc", resp, err)
	}

	if rOut.UscSyncAssociatedItems != nil {
		namespace, filterSecretValue, exists := common.GetRotatorUscSync(rOut.UscSyncAssociatedItems, uscName, remoteSecretName)
		if !exists {
			return nil, fmt.Errorf("static secret sync not found for secret name: %s, usc name: %s, remote secret name: %s", secretName, uscName, remoteSecretName)
		}
		err := d.Set("namespace", namespace)
		if err != nil {
			return nil, err
		}
		err = d.Set("filter_secret_value", filterSecretValue)
		if err != nil {
			return nil, err
		}
	}

	d.SetId(buildStaticUscSyncId(secretName, uscName, remoteSecretName))

	err = d.Set("name", secretName)
	if err != nil {
		return nil, err
	}
	err = d.Set("usc_name", uscName)
	if err != nil {
		return nil, err
	}
	err = d.Set("remote_secret_name", remoteSecretName)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

const staticUscSyncDelimiter string = "__"

func buildStaticUscSyncId(secretName, uscName, remoteSecretName string) string {
	return strings.Join([]string{secretName, uscName, remoteSecretName}, staticUscSyncDelimiter)
}

func extractStaticUscSyncFromId(id string) (string, string, string, error) {
	fields := strings.Split(id, staticUscSyncDelimiter)
	if len(fields) != 3 {
		return "", "", "", fmt.Errorf("invalid id format: %s. expected format 'secretName__uscName__remoteSecretName'", id)
	}
	return fields[0], fields[1], fields[2], nil
}
