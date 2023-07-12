// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/akeylesslabs/akeyless-go/v3"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceGatewayAllowedAccess() *schema.Resource {
	return &schema.Resource{
		Description: "Create gateway allowed access",
		Create:      resourceAllowedAccessCreate,
		Read:        resourceAllowedAccessRead,
		Update:      resourceAllowedAccessUpdate,
		Delete:      resourceAllowedAccessDelete,
		Importer: &schema.ResourceImporter{
			State: resourceAllowedAccessImport,
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
				Description: "The access id to be attached to this allowed access",
			},
			"sub_claims": {
				Type:        schema.TypeMap,
				Optional:    true,
				Description: "key/val of sub claims, e.g group=admins,developers",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"permissions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Comma-seperated list of permissions for this allowed access. Available permissions: [defaults,targets,classic_keys,automatic_migration,ldap_auth,dynamic_secret,k8s_auth,log_forwarding,zero_knowledge_encryption,rotated_secret,caching,event_forwarding,admin,kmip,general]",
			},
		},
	}
}

func resourceAllowedAccessCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	accessId := d.Get("access_id").(string)
	subClaims := readSubClaims(d)
	permissions := d.Get("permissions").(string)

	if err := validatePermissions(permissions); err != nil {
		return err
	}

	body := akeyless.GatewayCreateAllowedAccess{
		Name:      name,
		AccessId:  accessId,
		Token:     &token,
		SubClaims: &subClaims,
	}

	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Permissions, permissions)

	_, _, err := client.GatewayCreateAllowedAccess(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create gateway allowed access, error: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create gateway allowed access, error: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAllowedAccessRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless.GatewayGetAllowedAccess{
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
		err = d.Set("permissions", strings.Join(*rOut.Permissions, ","))
		if err != nil {
			return err
		}
	}

	d.SetId(path)

	return nil
}

func resourceAllowedAccessUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	description := d.Get("description").(string)
	accessId := d.Get("access_id").(string)
	subClaims := readSubClaims(d)
	permissions := d.Get("permissions").(string)

	if err := validatePermissions(permissions); err != nil {
		return err
	}

	body := akeyless.GatewayUpdateAllowedAccess{
		Name:      name,
		AccessId:  accessId,
		Token:     &token,
		SubClaims: &subClaims,
	}

	common.GetAkeylessPtr(&body.Description, description)
	common.GetAkeylessPtr(&body.Permissions, permissions)

	_, _, err := client.GatewayUpdateAllowedAccess(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update gateway allowed access, error: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update gateway allowed access, error: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceAllowedAccessDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	deleteItem := akeyless.GatewayDeleteAllowedAccess{
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

func resourceAllowedAccessImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	provider := m.(providerMeta)
	client := *provider.client
	token := *provider.token

	path := d.Id()

	item := akeyless.GatewayGetAllowedAccess{
		Name:  path,
		Token: &token,
	}

	ctx := context.Background()
	_, _, err := client.GatewayGetAllowedAccess(ctx).Body(item).Execute()
	if err != nil {
		return nil, err
	}

	err = d.Set("name", path)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}

type AccessPermission string

type Permissions []AccessPermission

const (
	AccessPermissionAny                     AccessPermission = "any" // internal permission, not used for the clients
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
)

var validAccessPermission = []AccessPermission{
	AccessPermissionAny,
	AccessPermissionDefaults,
	AccessPermissionTargets,
	AccessPermissionClassicKeys,
	AccessPermissionAutomaticMigration,
	AccessPermissionLdapAuth,
	AccessPermissionDynamicSecret,
	AccessPermissionK8sAuth,
	AccessPermissionLogForwarding,
	AccessPermissionZeroKnowledgeEncryption,
	AccessPermissionRotatedSecret,
	AccessPermissionCaching,
	AccessPermissionEventForwarding,
	AccessPermissionAdmin,
	AccessPermissionKmip,
	AccessPermissionGeneral,
}

func IsValidPermission(p string) bool {
	return common.SliceContains[AccessPermission](validAccessPermission, AccessPermission(p))
}

func validatePermissions(permissions string) error {
	if permissions != "" {
		perms := strings.Split(permissions, ",")
		permissionsList := make([]AccessPermission, len(perms))
		for i, p := range perms {
			p = strings.TrimSpace(p)
			if !IsValidPermission(p) {
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
