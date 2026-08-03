package akeyless

import (
	"context"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/go-cty/cty"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceGatewayMigrationK8s() *schema.Resource {
	return &schema.Resource{
		Description: "Kubernetes Migration resource",
		Create:      resourceGatewayMigrationK8sCreate,
		Read:        resourceGatewayMigrationK8sRead,
		Update:      resourceGatewayMigrationK8sUpdate,
		Delete:      resourceGatewayMigrationK8sDelete,
		Importer: &schema.ResourceImporter{
			State: resourceGatewayMigrationK8sImport,
		},
		ValidateRawResourceConfigFuncs: []schema.ValidateRawResourceConfigFunc{
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("k8s_token"), cty.GetAttrPath("k8s_token_wo")),
			validation.PreferWriteOnlyAttribute(cty.GetAttrPath("k8s_password"), cty.GetAttrPath("k8s_password_wo")),
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Migration name",
				ForceNew:    true,
			},
			"target_location": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Target location in Akeyless for imported secrets",
			},
			"k8s_url": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "K8s API Server URL, e.g. https://k8s-api.mycompany.com:6443 (relevant only for K8s migration)",
			},
			"k8s_token": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "For Token Authentication method K8s Bearer Token with sufficient permission to list and get secrets in the namespace(s) you selected (relevant only for K8s migration with Token Authentication method)",
			},
			"k8s_token_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "For Token Authentication method K8s Bearer Token with sufficient permission to list and get secrets in the namespace(s) you selected (relevant only for K8s migration with Token Authentication method) (write-only, not stored in state). Requires Terraform 1.11+. Bump k8s_token_wo_version to change it.",
			},
			"k8s_token_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for k8s_token_wo. Increment to update the value.",
			},
			"k8s_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "For Password Authentication method K8s Client username with sufficient permission to list and get secrets in the namespace(s) you selected (relevant only for K8s migration with Password Authentication method)",
			},
			"k8s_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "K8s Client password (relevant only for K8s migration with Password Authentication method)",
			},
			"k8s_password_wo": {
				Type:        schema.TypeString,
				Optional:    true,
				WriteOnly:   true,
				Description: "K8s Client password (relevant only for K8s migration with Password Authentication method) (write-only, not stored in state). Requires Terraform 1.11+. Bump k8s_password_wo_version to change it.",
			},
			"k8s_password_wo_version": {
				Type:        schema.TypeInt,
				Optional:    true,
				Description: "Version trigger for k8s_password_wo. Increment to update the value.",
			},
			"k8s_ca_certificate": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "For Certificate Authentication method K8s Cluster CA certificate (relevant only for K8s migration with Certificate Authentication method)",
				Elem:        &schema.Schema{Type: schema.TypeInt},
			},
			"k8s_client_certificate": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "K8s Client certificate with sufficient permission to list and get secrets in the namespace(s) you selected (relevant only for K8s migration with Certificate Authentication method)",
				Elem:        &schema.Schema{Type: schema.TypeInt},
			},
			"k8s_client_key": {
				Type:        schema.TypeList,
				Optional:    true,
				Description: "K8s Client key (relevant only for K8s migration with Certificate Authentication method)",
				Elem:        &schema.Schema{Type: schema.TypeInt},
			},
			"k8s_namespace": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "K8s Namespace, Use this field to import secrets from a particular namespace only. By default, the secrets are imported from all namespaces (relevant only for K8s migration)",
			},
			"k8s_skip_system": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "K8s Skip Control Plane Secrets, This option allows to avoid importing secrets from system namespaces (relevant only for K8s migration)",
			},
			"protection_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The name of a key that used to encrypt the secret value (if empty, the account default protectionKey key will be used)",
			},
			"migration_id": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Migration ID",
			},
		},
	}
}

func resourceGatewayMigrationK8sCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	k8sUrl := d.Get("k8s_url").(string)
	k8sToken, err := common.EffectiveSecretValue(d, "k8s_token", "k8s_token_wo")
	if err != nil {
		return err
	}
	k8sUsername := d.Get("k8s_username").(string)
	k8sPassword, err := common.EffectiveSecretValue(d, "k8s_password", "k8s_password_wo")
	if err != nil {
		return err
	}
	k8sCaCertificate := d.Get("k8s_ca_certificate").([]interface{})
	k8sClientCertificate := d.Get("k8s_client_certificate").([]interface{})
	k8sClientKey := d.Get("k8s_client_key").([]interface{})
	k8sNamespace := d.Get("k8s_namespace").(string)
	k8sSkipSystem := d.Get("k8s_skip_system").(bool)
	protectionKey := d.Get("protection_key").(string)

	body := akeyless_api.NewGatewayCreateMigration("", name, "", "", targetLocation)
	body.Token = &token
	body.Type = akeyless_api.PtrString("k8s")
	common.GetAkeylessPtr(&body.K8sUrl, k8sUrl)
	common.GetAkeylessPtr(&body.K8sToken, k8sToken)
	common.GetAkeylessPtr(&body.K8sUsername, k8sUsername)
	common.GetAkeylessPtr(&body.K8sPassword, k8sPassword)
	if len(k8sCaCertificate) > 0 {
		k8sCaCertificateInt32 := make([]int32, len(k8sCaCertificate))
		for i, v := range k8sCaCertificate {
			k8sCaCertificateInt32[i] = int32(v.(int))
		}
		body.K8sCaCertificate = k8sCaCertificateInt32
	}
	if len(k8sClientCertificate) > 0 {
		k8sClientCertificateInt32 := make([]int32, len(k8sClientCertificate))
		for i, v := range k8sClientCertificate {
			k8sClientCertificateInt32[i] = int32(v.(int))
		}
		body.K8sClientCertificate = k8sClientCertificateInt32
	}
	if len(k8sClientKey) > 0 {
		k8sClientKeyInt32 := make([]int32, len(k8sClientKey))
		for i, v := range k8sClientKey {
			k8sClientKeyInt32[i] = int32(v.(int))
		}
		body.K8sClientKey = k8sClientKeyInt32
	}
	common.GetAkeylessPtr(&body.K8sNamespace, k8sNamespace)
	common.GetAkeylessPtr(&body.K8sSkipSystem, k8sSkipSystem)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	out, resp, err := client.GatewayCreateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't create Gateway Migration K8s", resp, err)
	}

	migrationID := *out.MigrationId
	d.Set("migration_id", migrationID)

	d.SetId(name)

	return resourceGatewayMigrationK8sRead(d, m)
}

func resourceGatewayMigrationK8sRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.GatewayGetMigration{
		Name:  &path,
		Token: &token,
	}

	rOut, res, err := client.GatewayGetMigration(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get Gateway Migration K8s", res, err)
	}

	if rOut.Body != nil {
		if len(rOut.Body.K8sMigrations) > 0 {
			for _, migration := range rOut.Body.K8sMigrations {
				if migration.General != nil && *migration.General.Name == path {
					if migration.General.Id != nil {
						if err := d.Set("migration_id", *migration.General.Id); err != nil {
							return err
						}
					}
					if migration.General.ProtectionKey != nil {
						if err := d.Set("protection_key", *migration.General.ProtectionKey); err != nil {
							return err
						}
					}
					if migration.General.Prefix != nil {
						if err := d.Set("target_location", *migration.General.Prefix); err != nil {
							return err
						}
					}
					if migration.Payload != nil {
						if migration.Payload.Server != nil {
							if err := d.Set("k8s_url", *migration.Payload.Server); err != nil {
								return err
							}
						}
						if migration.Payload.Username != nil {
							if err := d.Set("k8s_username", *migration.Payload.Username); err != nil {
								return err
							}
						}
						if migration.Payload.Namespace != nil {
							if err := d.Set("k8s_namespace", *migration.Payload.Namespace); err != nil {
								return err
							}
						}
						if migration.Payload.SkipSystem != nil {
							if err := d.Set("k8s_skip_system", *migration.Payload.SkipSystem); err != nil {
								return err
							}
						}
					}
					break
				}
			}
		}
	}

	d.SetId(path)

	return nil
}

func resourceGatewayMigrationK8sUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	ctx := context.Background()
	name := d.Get("name").(string)
	targetLocation := d.Get("target_location").(string)
	k8sUrl := d.Get("k8s_url").(string)
	k8sToken, err := common.EffectiveSecretValue(d, "k8s_token", "k8s_token_wo")
	if err != nil {
		return err
	}
	k8sUsername := d.Get("k8s_username").(string)
	k8sPassword, err := common.EffectiveSecretValue(d, "k8s_password", "k8s_password_wo")
	if err != nil {
		return err
	}
	k8sCaCertificate := d.Get("k8s_ca_certificate").([]interface{})
	k8sClientCertificate := d.Get("k8s_client_certificate").([]interface{})
	k8sClientKey := d.Get("k8s_client_key").([]interface{})
	k8sNamespace := d.Get("k8s_namespace").(string)
	k8sSkipSystem := d.Get("k8s_skip_system").(bool)
	protectionKey := d.Get("protection_key").(string)

	body := akeyless_api.NewGatewayUpdateMigration("", "", "", targetLocation)
	body.Token = &token
	body.Name = &name
	common.GetAkeylessPtr(&body.K8sUrl, k8sUrl)
	common.GetAkeylessPtr(&body.K8sToken, k8sToken)
	common.GetAkeylessPtr(&body.K8sUsername, k8sUsername)
	common.GetAkeylessPtr(&body.K8sPassword, k8sPassword)
	if len(k8sCaCertificate) > 0 {
		k8sCaCertificateInt32 := make([]int32, len(k8sCaCertificate))
		for i, v := range k8sCaCertificate {
			k8sCaCertificateInt32[i] = int32(v.(int))
		}
		body.K8sCaCertificate = k8sCaCertificateInt32
	}
	if len(k8sClientCertificate) > 0 {
		k8sClientCertificateInt32 := make([]int32, len(k8sClientCertificate))
		for i, v := range k8sClientCertificate {
			k8sClientCertificateInt32[i] = int32(v.(int))
		}
		body.K8sClientCertificate = k8sClientCertificateInt32
	}
	if len(k8sClientKey) > 0 {
		k8sClientKeyInt32 := make([]int32, len(k8sClientKey))
		for i, v := range k8sClientKey {
			k8sClientKeyInt32[i] = int32(v.(int))
		}
		body.K8sClientKey = k8sClientKeyInt32
	}
	common.GetAkeylessPtr(&body.K8sNamespace, k8sNamespace)
	common.GetAkeylessPtr(&body.K8sSkipSystem, k8sSkipSystem)
	common.GetAkeylessPtr(&body.ProtectionKey, protectionKey)

	_, resp, err := client.GatewayUpdateMigration(ctx).Body(*body).Execute()
	if err != nil {
		return common.HandleError("can't update Gateway Migration K8s", resp, err)
	}

	return nil
}

func resourceGatewayMigrationK8sDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	id := d.Get("migration_id").(string)

	deleteItem := akeyless_api.GatewayDeleteMigration{
		Token: &token,
		Id:    id,
	}

	ctx := context.Background()
	_, _, err := client.GatewayDeleteMigration(ctx).Body(deleteItem).Execute()
	if err != nil {
		return err
	}

	return nil
}

func resourceGatewayMigrationK8sImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceGatewayMigrationK8sRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
