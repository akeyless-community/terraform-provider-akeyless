// generated file
package akeyless

import (
	"context"
	"fmt"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/google/uuid"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceCertificateDiscovery() *schema.Resource {
	return &schema.Resource{
		Description: "Certificate Discovery resource. Starts a certificate discovery scan and saves results under the target location. Destroying this resource removes it from Terraform state only and does not delete discovered certificates.",
		Create:      resourceCertificateDiscoveryCreate,
		Read:        resourceCertificateDiscoveryRead,
		Delete:      resourceCertificateDiscoveryDelete,
		Importer: &schema.ResourceImporter{
			State: resourceCertificateDiscoveryImport,
		},
		Schema: map[string]*schema.Schema{
			"hosts": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "A comma separated list of IPs, CIDR ranges, or DNS names to scan",
			},
			"port_ranges": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Default:     "443",
				Description: "A comma separated list of port ranges. Example: 80,8080-8085",
			},
			"target_location": {
				Type:             schema.TypeString,
				Required:         true,
				ForceNew:         true,
				Description:      "The results will be saved in this folder",
				DiffSuppressFunc: common.DiffSuppressOnLeadingSlash,
			},
			"expiration_event_in": {
				Type:        schema.TypeSet,
				Optional:    true,
				ForceNew:    true,
				Description: "How many days before the expiration of the certificate would you like to be notified. To specify multiple events, repeat this argument.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"protection_key": {
				Type:        schema.TypeString,
				Optional:    true,
				ForceNew:    true,
				Description: "The name of the key that protects the certificate value (if empty, the account default key will be used)",
			},
			"count_new": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Number of new certificates discovered",
			},
			"count_existing": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Number of existing certificates updated",
			},
			"count_hosts": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Number of hosts scanned",
			},
			"count_failed": {
				Type:        schema.TypeInt,
				Computed:    true,
				Description: "Number of failed scan targets",
			},
			"item_names": {
				Type:        schema.TypeList,
				Computed:    true,
				Description: "Names of certificate items created or updated by the discovery",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceCertificateDiscoveryCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	hosts := strings.ReplaceAll(d.Get("hosts").(string), " ", "")
	portRanges := strings.ReplaceAll(d.Get("port_ranges").(string), " ", "")
	targetLocation := d.Get("target_location").(string)
	expirationEventInSet := d.Get("expiration_event_in").(*schema.Set)
	expirationEventIn := common.ExpandStringList(expirationEventInSet.List())
	protectionKey := d.Get("protection_key").(string)

	if hosts == "" {
		return fmt.Errorf("hosts cannot be empty")
	}

	body := akeyless_api.CertificateDiscovery{
		Hosts:          hosts,
		TargetLocation: targetLocation,
		Token:          &token,
	}
	common.GetAkeylessPtr(&body.PortRanges, portRanges)
	common.GetAkeylessPtr(&body.ExpirationEventIn, expirationEventIn)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	out, resp, err := client.CertificateDiscovery(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't run certificate discovery", resp, err)
	}

	countNew, countExisting, countHosts, countFailed := 0, 0, 0, 0
	itemNames := []string{}
	if out != nil && out.Results != nil {
		results := out.Results
		if results.CountNew != nil {
			countNew = int(*results.CountNew)
		}
		if results.CountExisting != nil {
			countExisting = int(*results.CountExisting)
		}
		if results.CountHosts != nil {
			countHosts = int(*results.CountHosts)
		}
		if results.CountFailed != nil {
			countFailed = int(*results.CountFailed)
		}
		if results.ItemNames != nil {
			itemNames = results.ItemNames
		}
	}
	if err := d.Set("count_new", countNew); err != nil {
		return err
	}
	if err := d.Set("count_existing", countExisting); err != nil {
		return err
	}
	if err := d.Set("count_hosts", countHosts); err != nil {
		return err
	}
	if err := d.Set("count_failed", countFailed); err != nil {
		return err
	}
	if err := d.Set("item_names", itemNames); err != nil {
		return err
	}

	d.SetId(uuid.New().String())
	return nil
}

func resourceCertificateDiscoveryRead(d *schema.ResourceData, m interface{}) error {
	// Discovery is a one-shot scan with no get/describe API; retain Terraform state.
	return nil
}

func resourceCertificateDiscoveryDelete(d *schema.ResourceData, m interface{}) error {
	// Destroying the resource only removes it from Terraform state.
	// Discovered certificate items are left intact.
	d.SetId("")
	return nil
}

func resourceCertificateDiscoveryImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	return nil, fmt.Errorf("certificate discovery cannot be imported because it is a one-shot scan with no remote identity")
}
