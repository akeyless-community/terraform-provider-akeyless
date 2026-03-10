// generated file
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayAllowedAccess() *schema.Resource {
	return &schema.Resource{
		Description: "Create gateway allowed access",
		Create:      resourceGatewayAllowedAccessCreate,
		Read:        resourceGatewayAllowedAccessRead,
		Update:      resourceGatewayAllowedAccessUpdate,
		Delete:      resourceGatewayAllowedAccessDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayAllowedAccessImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Allowed access name",
				ForceNew:    true,
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Allowed access description",
			},
			"access_id": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "The access id to be attached to this allowed access. Auth method with this access id should already exist.",
			},
			"sub_claims": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "Sub claims key/val of sub claims, e.g group=admins,developers",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"permissions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Permissions Comma-seperated list of permissions for this allowed access. Available permissions: [defaults,targets,classic_keys,automatic_migration,ldap_auth,dynamic_secret,k8s_auth,log_forwarding,zero_knowledge_encryption,rotated_secret,caching,event_forwarding,admin,kmip,general,rotate_secret_value]",
			},
			"case_sensitive": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Treat sub claims as case-sensitive [true/false]",
			},
			"sub_claims_case_insensitive": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Treat sub claims as case-insensitive",
			},
			"access_type": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Access type",
			},
			"cluster_id": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Cluster ID",
			},
			"created_at": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Creation timestamp",
			},
			"editable": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Whether the allowed access is editable",
			},
			"error": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Error message if any",
			},
			"id_int": {
				Type:        schema.TypeInt,
				Optional:    true,
				Computed:    true,
				Description: "Internal ID",
			},
			"is_valid": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Whether the allowed access is valid",
			},
			"updated_at": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Last update timestamp",
			},
		},
	}
}

func resourceGatewayAllowedAccessCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	accessId := d.Get("access_id").(string)
	subClaims := readSubClaims(d)
	permissions := d.Get("permissions").(string)
	caseSensitive := d.Get("case_sensitive").(string)
	subClaimsCaseInsensitive := d.Get("sub_claims_case_insensitive").(bool)

	if err := validatePermissions(permissions); err != nil {
		return err
	}

	body := akeyless_api.GatewayCreateAllowedAccess{
		Name:      name,
		AccessId:  accessId,
		Token:     &token,
		SubClaims: &subClaims,
	}

	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Permissions, permissions)
	common.GetAkeylessPtr(&body.CaseSensitive, caseSensitive)
	if d.HasChange("sub_claims_case_insensitive") || subClaimsCaseInsensitive {
		body.SubClaimsCaseInsensitive = &subClaimsCaseInsensitive
	}

	_, resp, err := client.GatewayCreateAllowedAccess(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create gateway allowed access, error", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceGatewayAllowedAccessRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.GatewayGetAllowedAccess{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.GatewayGetAllowedAccess(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			if res.StatusCode == http.StatusNotFound {
				// The resource was deleted outside of the current Terraform workspace, so invalidate this resource
				d.SetId("")
				return nil
			}
			return fmt.Errorf("can't get gateway allowed access: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't get gateway allowed access: %v", err)
	}
	if rOut.Name != nil {
		err = d.Set("name", *rOut.Name)
		if err != nil {
			return err
		}
	}
	if rOut.Description != nil {
		err = d.Set("description", *rOut.Description)
		if err != nil {
			return err
		}
	}
	if rOut.AccessId != nil {
		err = d.Set("access_id", *rOut.AccessId)
		if err != nil {
			return err
		}
	}
	if rOut.SubClaims != nil {
		sc := make(map[string]string, len(*rOut.SubClaims))
		for k, v := range *rOut.SubClaims {
			sc[k] = strings.Join(v, ",")
		}
		err := d.Set("sub_claims", sc)
		if err != nil {
			return err
		}
	}
	if rOut.Permissions != nil {
		err = d.Set("permissions", strings.Join(rOut.Permissions, ","))
		if err != nil {
			return err
		}
	}
	if rOut.SubClaimsCaseInsensitive != nil {
		err = d.Set("sub_claims_case_insensitive", *rOut.SubClaimsCaseInsensitive)
		if err != nil {
			return err
		}
	}
	if rOut.AccessType != nil {
		err = d.Set("access_type", *rOut.AccessType)
		if err != nil {
			return err
		}
	}
	if rOut.ClusterId != nil {
		err = d.Set("cluster_id", int(*rOut.ClusterId))
		if err != nil {
			return err
		}
	}
	if rOut.CreatedAt != nil {
		err = d.Set("created_at", rOut.CreatedAt.Format("2006-01-02T15:04:05Z07:00"))
		if err != nil {
			return err
		}
	}
	if rOut.Editable != nil {
		err = d.Set("editable", *rOut.Editable)
		if err != nil {
			return err
		}
	}
	if rOut.Error != nil {
		err = d.Set("error", *rOut.Error)
		if err != nil {
			return err
		}
	}
	if rOut.Id != nil {
		err = d.Set("id_int", int(*rOut.Id))
		if err != nil {
			return err
		}
	}
	if rOut.IsValid != nil {
		err = d.Set("is_valid", *rOut.IsValid)
		if err != nil {
			return err
		}
	}
	if rOut.UpdatedAt != nil {
		err = d.Set("updated_at", rOut.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"))
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceGatewayAllowedAccessUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	accessId := d.Get("access_id").(string)
	subClaims := readSubClaims(d)
	permissions := d.Get("permissions").(string)
	caseSensitive := d.Get("case_sensitive").(string)
	subClaimsCaseInsensitive := d.Get("sub_claims_case_insensitive").(bool)

	if err := validatePermissions(permissions); err != nil {
		return err
	}

	body := akeyless_api.GatewayUpdateAllowedAccess{
		Name:      name,
		AccessId:  accessId,
		Token:     &token,
		SubClaims: &subClaims,
	}

	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Permissions, permissions)
	common.GetAkeylessPtr(&body.CaseSensitive, caseSensitive)
	if d.HasChange("sub_claims_case_insensitive") || subClaimsCaseInsensitive {
		body.SubClaimsCaseInsensitive = &subClaimsCaseInsensitive
	}

	_, resp, err := client.GatewayUpdateAllowedAccess(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update gateway allowed access, error", resp, err)
	}

	d.SetId(name)

	return nil
}

func resourceGatewayAllowedAccessDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless_api.GatewayDeleteAllowedAccess{
		Token: &token,
		Name:  path,
	}

	ctx := context.Background()
	_, _, err := client.GatewayDeleteAllowedAccess(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceGatewayAllowedAccessImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceGatewayAllowedAccessRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

type AccessPermission string

type Permissions []AccessPermission

const (
	AccessPermissionDefaults                AccessPermission = "defaults"
	AccessPermissionTargets                 AccessPermission = "targets"
	AccessPermissionClassicKeys             AccessPermission = "classic_keys"
	AccessPermissionAutomaticMigration      AccessPermission = "automatic_migration"
	AccessPermissionLdapAuth                AccessPermission = "ldap_auth"
	AccessPermissionDynamicSecret           AccessPermission = "dynamic_secret"
	AccessPermissionK8sAuth                 AccessPermission = "k8s_auth"
	AccessPermissionLogForwarding           AccessPermission = "log_forwarding"
	AccessPermissionZeroKnowledgeEncryption AccessPermission = "zero_knowledge_encryption"
	AccessPermissionRotatedSecret           AccessPermission = "rotated_secret"
	AccessPermissionCaching                 AccessPermission = "caching"
	AccessPermissionEventForwarding         AccessPermission = "event_forwarding"
	AccessPermissionAdmin                   AccessPermission = "admin"
	AccessPermissionKmip                    AccessPermission = "kmip"
	AccessPermissionGeneral                 AccessPermission = "general"
	AccessPermissionRotateSecretValue       AccessPermission = "rotate_secret_value"
)

var validAccessPermission = map[AccessPermission]bool{
	AccessPermissionDefaults:                true,
	AccessPermissionTargets:                 true,
	AccessPermissionClassicKeys:             true,
	AccessPermissionAutomaticMigration:      true,
	AccessPermissionLdapAuth:                true,
	AccessPermissionDynamicSecret:           true,
	AccessPermissionK8sAuth:                 true,
	AccessPermissionLogForwarding:           true,
	AccessPermissionZeroKnowledgeEncryption: true,
	AccessPermissionRotatedSecret:           true,
	AccessPermissionCaching:                 true,
	AccessPermissionEventForwarding:         true,
	AccessPermissionAdmin:                   true,
	AccessPermissionKmip:                    true,
	AccessPermissionGeneral:                 true,
	AccessPermissionRotateSecretValue:       true,
}

func isValidPermission(p string) bool {
	_, ok := validAccessPermission[AccessPermission(p)]
	return ok
}

func validatePermissions(permissions string) error {
	if permissions != "" {
		perms := strings.Split(permissions, ",")
		permissionsList := make([]AccessPermission, len(perms))
		for i, p := range perms {
			p = strings.TrimSpace(p)
			if !isValidPermission(p) {
				return fmt.Errorf("invalid permission value: %q", p)
			}
			permissionsList[i] = AccessPermission(p)
		}
	}
	return nil
}

func readSubClaims(d *schema.ResourceData) map[string]string {
	subClaims := d.Get("sub_claims").(map[string]interface{})
	sc := make(map[string]string, len(subClaims))
	for k, v := range subClaims {
		sc[k] = v.(string)
	}
	return sc
}
