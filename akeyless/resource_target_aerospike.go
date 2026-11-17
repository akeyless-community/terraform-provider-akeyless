// generated file
package akeyless

import (
	"context"
	"strconv"

	akeyless_api "github.com/akeylesslabs/akeyless-go/v5"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceAerospikeTarget() *schema.Resource {
	return &schema.Resource{
		Description: "Aerospike target resource",
		Create:      resourceAerospikeTargetCreate, Read: resourceAerospikeTargetRead,
		Update: resourceAerospikeTargetUpdate, Delete: resourceAerospikeTargetDelete,
		Importer: &schema.ResourceImporter{State: resourceAerospikeTargetImport},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				ForceNew:    true,
				Description: "Target name",
			},
			"admin_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Aerospike admin username",
			},
			"password": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Aerospike admin password",
			},
			"hostname": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Aerospike host address",
			},
			"port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Aerospike port",
			},
			"namespace": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Aerospike namespace",
			},
			"aerospike_cloud": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Aerospike Cloud deployment",
			},
			"aerospike_client_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Aerospike Cloud client ID",
			},
			"aerospike_client_secret": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Aerospike Cloud client secret",
			},
			"aerospike_cluster_id": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Aerospike Cloud cluster ID",
			},
			"ssl": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable SSL",
			},
			"ssl_certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "SSL CA certificate",
			},
			"db_server_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "TLS server name",
			},
			"skip_server_name_validation": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Skip server name validation",
			},
			"enable_mtls": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable mutual TLS",
			},
			"client_certificate": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Client certificate",
			},
			"client_private_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Description: "Client private key",
			},
			"rotate_on_unlock": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Rotate after unlock",
			},
			"lock_on_read": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Lock after read",
			},
			"lock_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Lock TTL in minutes",
			},
			"key": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "Protection key",
			},
			"description": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Description",
			},
			"max_versions": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Maximum versions",
			},
			"keep_prev_version": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Keep previous version",
			},
			"delete_protection": {
				Type:        schema.TypeString,
				Optional:    true,
				Default:     "false",
				Description: "Delete protection",
			},
		},
	}
}

func resourceAerospikeTargetCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client, token := *provider.client, *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)
	body := akeyless_api.TargetCreateAerospike{Name: name, Token: &token}
	common.GetAkeylessPtr(&body.AdminUsername, d.Get("admin_username").(string))
	common.GetAkeylessPtr(&body.Password, d.Get("password").(string))
	common.GetAkeylessPtr(&body.Hostname, d.Get("hostname").(string))
	common.GetAkeylessPtr(&body.Port, d.Get("port").(string))
	common.GetAkeylessPtr(&body.Namespace, d.Get("namespace").(string))
	common.GetAkeylessPtr(&body.AerospikeCloud, d.Get("aerospike_cloud").(bool))
	common.GetAkeylessPtr(&body.AerospikeClientId, d.Get("aerospike_client_id").(string))
	common.GetAkeylessPtr(&body.AerospikeClientSecret, d.Get("aerospike_client_secret").(string))
	common.GetAkeylessPtr(&body.AerospikeClusterId, d.Get("aerospike_cluster_id").(string))
	common.GetAkeylessPtr(&body.Ssl, d.Get("ssl").(bool))
	common.GetAkeylessPtr(&body.SslCertificate, d.Get("ssl_certificate").(string))
	common.GetAkeylessPtr(&body.DbServerName, d.Get("db_server_name").(string))
	common.GetAkeylessPtr(&body.SkipServerNameValidation, d.Get("skip_server_name_validation").(string))
	common.GetAkeylessPtr(&body.EnableMtls, d.Get("enable_mtls").(bool))
	common.GetAkeylessPtr(&body.ClientCertificate, d.Get("client_certificate").(string))
	common.GetAkeylessPtr(&body.ClientPrivateKey, d.Get("client_private_key").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))
	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))

	_, resp, err := client.TargetCreateAerospike(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't create target", resp, err)
	}
	if keepPrevVersion := d.Get("keep_prev_version").(string); keepPrevVersion != "" {
		updateBody := akeyless_api.TargetUpdateAerospike{Name: name, Token: &token}
		common.GetAkeylessPtr(&updateBody.KeepPrevVersion, keepPrevVersion)
		_, resp, err = client.TargetUpdateAerospike(ctx).Body(updateBody).Execute()
		if err != nil {
			return common.HandleError("can't update target", resp, err)
		}
	}
	d.SetId(name)
	return nil
}

func resourceAerospikeTargetUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client, token := *provider.client, *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)

	body := akeyless_api.TargetUpdateAerospike{Name: name, Token: &token}
	common.GetAkeylessPtr(&body.AdminUsername, d.Get("admin_username").(string))
	common.GetAkeylessPtr(&body.Password, d.Get("password").(string))
	common.GetAkeylessPtr(&body.Hostname, d.Get("hostname").(string))
	common.GetAkeylessPtr(&body.Port, d.Get("port").(string))
	common.GetAkeylessPtr(&body.Namespace, d.Get("namespace").(string))
	common.GetAkeylessPtr(&body.AerospikeCloud, d.Get("aerospike_cloud").(bool))
	common.GetAkeylessPtr(&body.AerospikeClientId, d.Get("aerospike_client_id").(string))
	common.GetAkeylessPtr(&body.AerospikeClientSecret, d.Get("aerospike_client_secret").(string))
	common.GetAkeylessPtr(&body.AerospikeClusterId, d.Get("aerospike_cluster_id").(string))
	common.GetAkeylessPtr(&body.Ssl, d.Get("ssl").(bool))
	common.GetAkeylessPtr(&body.SslCertificate, d.Get("ssl_certificate").(string))
	common.GetAkeylessPtr(&body.DbServerName, d.Get("db_server_name").(string))
	common.GetAkeylessPtr(&body.SkipServerNameValidation, d.Get("skip_server_name_validation").(string))
	common.GetAkeylessPtr(&body.EnableMtls, d.Get("enable_mtls").(bool))
	common.GetAkeylessPtr(&body.ClientCertificate, d.Get("client_certificate").(string))
	common.GetAkeylessPtr(&body.ClientPrivateKey, d.Get("client_private_key").(string))
	common.GetAkeylessPtr(&body.RotateOnUnlock, d.Get("rotate_on_unlock").(string))
	common.GetAkeylessPtr(&body.LockOnRead, d.Get("lock_on_read").(string))
	common.GetAkeylessPtr(&body.LockTtl, d.Get("lock_ttl").(string))
	common.GetAkeylessPtr(&body.Key, d.Get("key").(string))
	common.GetAkeylessPtr(&body.Description, d.Get("description").(string))
	common.GetAkeylessPtr(&body.MaxVersions, d.Get("max_versions").(string))
	common.GetAkeylessPtr(&body.KeepPrevVersion, d.Get("keep_prev_version").(string))
	common.GetAkeylessPtr(&body.DeleteProtection, d.Get("delete_protection").(string))

	_, resp, err := client.TargetUpdateAerospike(ctx).Body(body).Execute()
	if err != nil {
		return common.HandleError("can't update target", resp, err)
	}
	d.SetId(name)
	return nil
}

func resourceAerospikeTargetRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	out, resp, err := provider.client.TargetGetDetails(context.Background()).Body(akeyless_api.TargetGetDetails{Name: d.Id(), Token: provider.token}).Execute()
	if err != nil {
		return common.HandleReadError(d, "can't get target details", resp, err)
	}
	if out.Target != nil && out.Target.ProtectionKeyName != nil {
		if err := d.Set("key", *out.Target.ProtectionKeyName); err != nil {
			return err
		}
	}
	if out.Target != nil && out.Target.Comment != nil {
		if err := d.Set("description", *out.Target.Comment); err != nil {
			return err
		}
	}
	if out.Target != nil && out.Target.DeleteProtection != nil {
		if err := d.Set("delete_protection", strconv.FormatBool(*out.Target.DeleteProtection)); err != nil {
			return err
		}
	}
	if out.Value != nil && out.Value.AerospikeTargetDetails != nil {
		details := out.Value.AerospikeTargetDetails
		set := func(key string, value interface{}) error {
			if err := d.Set(key, value); err != nil {
				return err
			}
			return nil
		}
		if details.AerospikeAdminUsername != nil {
			if err := set("admin_username", *details.AerospikeAdminUsername); err != nil {
				return err
			}
		}
		if details.AerospikePassword != nil {
			if err := set("password", *details.AerospikePassword); err != nil {
				return err
			}
		}
		if details.AerospikeHostname != nil {
			if err := set("hostname", *details.AerospikeHostname); err != nil {
				return err
			}
		}
		if details.AerospikePort != nil {
			if err := set("port", *details.AerospikePort); err != nil {
				return err
			}
		}
		if details.AerospikeNamespace != nil {
			if err := set("namespace", *details.AerospikeNamespace); err != nil {
				return err
			}
		}
		if details.AerospikeCloud != nil {
			if err := set("aerospike_cloud", *details.AerospikeCloud); err != nil {
				return err
			}
		}
		if details.AerospikeClientId != nil {
			if err := set("aerospike_client_id", *details.AerospikeClientId); err != nil {
				return err
			}
		}
		if details.AerospikeClientSecret != nil {
			if err := set("aerospike_client_secret", *details.AerospikeClientSecret); err != nil {
				return err
			}
		}
		if details.AerospikeClusterId != nil {
			if err := set("aerospike_cluster_id", *details.AerospikeClusterId); err != nil {
				return err
			}
		}
		if details.AerospikeSslConnectionMode != nil {
			if err := set("ssl", *details.AerospikeSslConnectionMode); err != nil {
				return err
			}
		}
		if details.AerospikeSslConnectionCertificate != nil {
			if err := set("ssl_certificate", *details.AerospikeSslConnectionCertificate); err != nil {
				return err
			}
		}
		if details.AerospikeDbServerName != nil {
			if err := set("db_server_name", *details.AerospikeDbServerName); err != nil {
				return err
			}
		}
		if details.AerospikeSkipServerNameValidation != nil {
			if err := set("skip_server_name_validation", *details.AerospikeSkipServerNameValidation); err != nil {
				return err
			}
		}
		if details.AerospikeEnableMtls != nil {
			if err := set("enable_mtls", *details.AerospikeEnableMtls); err != nil {
				return err
			}
		}
		if details.AerospikeClientCertificate != nil {
			if err := set("client_certificate", *details.AerospikeClientCertificate); err != nil {
				return err
			}
		}
		if details.AerospikeClientPrivateKey != nil {
			if err := set("client_private_key", *details.AerospikeClientPrivateKey); err != nil {
				return err
			}
		}
	}
	return nil
}

func resourceAerospikeTargetDelete(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	_, _, err := provider.client.TargetDelete(context.Background()).Body(akeyless_api.TargetDelete{
		Name: d.Id(), Token: provider.token,
	}).Execute()
	return err
}

func resourceAerospikeTargetImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {
	if err := resourceAerospikeTargetRead(d, m); err != nil {
		return nil, err
	}
	if err := d.Set("name", d.Id()); err != nil {
		return nil, err
	}
	return []*schema.ResourceData{d}, nil
}
