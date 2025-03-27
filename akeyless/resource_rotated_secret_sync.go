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

func resourceRotatedSecretSync() *schema.Resource {
	return &schema.Resource{
		Description: "Sync Rotated Secret with Universal Secrets Connector resource",
		Create:      resourceRotatedSecretSyncCreate,
		Read:        resourceRotatedSecretSyncRead,
		Update:      resourceRotatedSecretSyncUpdate,
		Delete:      resourceRotatedSecretSyncDelete,
		Importer: &schema.ResourceImporter{
			State: resourceRotatedSecretSyncImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Rotated Secret name",
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
		},
	}
}

func resourceRotatedSecretSyncCreate(d *schema.ResourceData, m any) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	rsName := d.Get("name").(string)
	uscName := d.Get("usc_name").(string)
	remoteSecretName := d.Get("remote_secret_name").(string)
	namespace := d.Get("namespace").(string)

	body := akeyless_api.RotatedSecretSync{
		Name:  rsName,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.UscName, uscName)
	common.GetAkeylessPtr(&body.RemoteSecretName, remoteSecretName)
	common.GetAkeylessPtr(&body.Namespace, namespace)

	_, resp, err := client.RotatedSecretSync(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't sync rotated secret", resp, err)
	}

	d.SetId(buildRsUscSyncId(rsName, uscName, remoteSecretName))

	return nil
}

func resourceRotatedSecretSyncRead(d *schema.ResourceData, m any) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	rsName, uscName, remoteSecretName, err := extractRsUscSyncFromId(d.Id())
	if err != nil {
		return err
	}

	body := akeyless_api.DescribeItem{
		Name:  rsName,
		Token: &token,
	}

	rOut, resp, err := client.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get usc", resp, err)
	}

	if rOut.UscSyncAssociatedItems != nil {
		namespace, exists := common.GetRotatorUscSync(rOut.UscSyncAssociatedItems, uscName, remoteSecretName)
		if !exists {
			return fmt.Errorf("rotated secret sync not found for rotated secret name: %s, usc name: %s, remote secret name: %s", rsName, uscName, remoteSecretName)
		}
		err := d.Set("namespace", namespace)
		if err != nil {
			return err
		}
	}

	d.SetId(buildRsUscSyncId(rsName, uscName, remoteSecretName))

	return nil
}

func resourceRotatedSecretSyncUpdate(d *schema.ResourceData, m any) error {
	return nil
}

func resourceRotatedSecretSyncDelete(d *schema.ResourceData, m any) error {

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	rsName, uscName, _, err := extractRsUscSyncFromId(d.Id())
	if err != nil {
		return err
	}

	deleteItem := akeyless_api.RotatedSecretDeleteSync{
		Token:   &token,
		Name:    rsName,
		UscName: uscName,
	}

	_, _, err = client.RotatedSecretDeleteSync(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceRotatedSecretSyncImport(d *schema.ResourceData, m any) ([]*schema.ResourceData, error) {

	ctx := context.Background()

	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	rsName, uscName, remoteSecretName, err := extractRsUscSyncFromId(d.Id())
	if err != nil {
		return nil, err
	}

	body := akeyless_api.DescribeItem{
		Name:  rsName,
		Token: &token,
	}

	rOut, resp, err := client.DescribeItem(ctx).Body(body).Execute()
	if err != nil {
		return nil, common.HandleReadError(d, "can't get usc", resp, err)
	}

	if rOut.UscSyncAssociatedItems != nil {
		namespace, exists := common.GetRotatorUscSync(rOut.UscSyncAssociatedItems, uscName, remoteSecretName)
		if !exists {
			return nil, fmt.Errorf("rotated secret sync not found for rotated secret name: %s, usc name: %s, remote secret name: %s", rsName, uscName, remoteSecretName)
		}
		err := d.Set("namespace", namespace)
		if err != nil {
			return nil, err
		}
	}

	d.SetId(buildRsUscSyncId(rsName, uscName, remoteSecretName))

	err = d.Set("name", rsName)
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

const rsUscSyncDelimiter string = "__"

func buildRsUscSyncId(rsName, uscName, remoteSecretName string) string {
	return strings.Join([]string{rsName, uscName, remoteSecretName}, rsUscSyncDelimiter)
}

func extractRsUscSyncFromId(id string) (string, string, string, error) {
	fields := strings.Split(id, rsUscSyncDelimiter)
	if len(fields) != 3 {
		return "", "", "", fmt.Errorf("invalid id format: %s. expected format 'rotatedSecretName__uscName__remoteSecretName'", id)
	}
	return fields[0], fields[1], fields[2], nil
}
