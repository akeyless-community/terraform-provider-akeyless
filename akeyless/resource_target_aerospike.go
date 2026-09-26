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
			"name":                        {Type: schema.TypeString, Required: true, ForceNew: true, Description: "Target name"},
			"admin_username":              {Type: schema.TypeString, Optional: true, Sensitive: true, Description: "Aerospike admin username"},
			"password":                    {Type: schema.TypeString, Optional: true, Sensitive: true, Description: "Aerospike admin password"},
			"hostname":                    {Type: schema.TypeString, Optional: true, Description: "Aerospike host address"},
			"port":                        {Type: schema.TypeString, Optional: true, Description: "Aerospike port"},
			"namespace":                   {Type: schema.TypeString, Optional: true, Description: "Aerospike namespace"},
			"aerospike_cloud":             {Type: schema.TypeBool, Optional: true, Description: "Aerospike Cloud deployment"},
			"aerospike_client_id":         {Type: schema.TypeString, Optional: true, Description: "Aerospike Cloud client ID"},
			"aerospike_client_secret":     {Type: schema.TypeString, Optional: true, Sensitive: true, Description: "Aerospike Cloud client secret"},
			"aerospike_cluster_id":        {Type: schema.TypeString, Optional: true, Description: "Aerospike Cloud cluster ID"},
			"ssl":                         {Type: schema.TypeBool, Optional: true, Description: "Enable SSL"},
			"ssl_certificate":             {Type: schema.TypeString, Optional: true, Sensitive: true, Description: "SSL CA certificate"},
			"db_server_name":              {Type: schema.TypeString, Optional: true, Description: "TLS server name"},
			"skip_server_name_validation": {Type: schema.TypeString, Optional: true, Description: "Skip server name validation"},
			"enable_mtls":                 {Type: schema.TypeBool, Optional: true, Description: "Enable mutual TLS"},
			"client_certificate":          {Type: schema.TypeString, Optional: true, Sensitive: true, Description: "Client certificate"},
			"client_private_key":          {Type: schema.TypeString, Optional: true, Sensitive: true, Description: "Client private key"},
			"rotate_on_unlock":            {Type: schema.TypeString, Optional: true, Description: "Rotate after unlock"},
			"lock_on_read":                {Type: schema.TypeString, Optional: true, Description: "Lock after read"},
			"lock_ttl":                    {Type: schema.TypeString, Optional: true, Description: "Lock TTL in minutes"},
			"key":                         {Type: schema.TypeString, Optional: true, Computed: true, Description: "Protection key"},
			"description":                 {Type: schema.TypeString, Optional: true, Description: "Description"},
			"max_versions":                {Type: schema.TypeString, Optional: true, Description: "Maximum versions"},
			"keep_prev_version":           {Type: schema.TypeString, Optional: true, Description: "Keep previous version"},
			"delete_protection":           {Type: schema.TypeString, Optional: true, Default: "false", Description: "Delete protection"},
		},
	}
}

func resourceAerospikeTargetCreate(d *schema.ResourceData, m interface{}) error {
	return resourceAerospikeTargetWrite(d, m, false)
}

func resourceAerospikeTargetUpdate(d *schema.ResourceData, m interface{}) error {
	return resourceAerospikeTargetWrite(d, m, true)
}

func resourceAerospikeTargetWrite(d *schema.ResourceData, m interface{}, update bool) error {
	provider := m.(*providerMeta)
	client, token := *provider.client, *provider.token
	ctx := context.Background()
	name := d.Get("name").(string)
	set := func(dst interface{}, key string) { common.GetAkeylessPtr(dst, d.Get(key)) }
	var body interface{}
	if update {
		b := akeyless_api.TargetUpdateAerospike{Name: name, Token: &token}
		set(&b.AdminUsername, "admin_username")
		set(&b.Password, "password")
		set(&b.Hostname, "hostname")
		set(&b.Port, "port")
		set(&b.Namespace, "namespace")
		set(&b.AerospikeCloud, "aerospike_cloud")
		set(&b.AerospikeClientId, "aerospike_client_id")
		set(&b.AerospikeClientSecret, "aerospike_client_secret")
		set(&b.AerospikeClusterId, "aerospike_cluster_id")
		set(&b.Ssl, "ssl")
		set(&b.SslCertificate, "ssl_certificate")
		set(&b.DbServerName, "db_server_name")
		set(&b.SkipServerNameValidation, "skip_server_name_validation")
		set(&b.EnableMtls, "enable_mtls")
		set(&b.ClientCertificate, "client_certificate")
		set(&b.ClientPrivateKey, "client_private_key")
		set(&b.RotateOnUnlock, "rotate_on_unlock")
		set(&b.LockOnRead, "lock_on_read")
		set(&b.LockTtl, "lock_ttl")
		set(&b.Key, "key")
		set(&b.Description, "description")
		set(&b.MaxVersions, "max_versions")
		set(&b.KeepPrevVersion, "keep_prev_version")
		set(&b.DeleteProtection, "delete_protection")
		body = b
	} else {
		b := akeyless_api.TargetCreateAerospike{Name: name, Token: &token}
		set(&b.AdminUsername, "admin_username")
		set(&b.Password, "password")
		set(&b.Hostname, "hostname")
		set(&b.Port, "port")
		set(&b.Namespace, "namespace")
		set(&b.AerospikeCloud, "aerospike_cloud")
		set(&b.AerospikeClientId, "aerospike_client_id")
		set(&b.AerospikeClientSecret, "aerospike_client_secret")
		set(&b.AerospikeClusterId, "aerospike_cluster_id")
		set(&b.Ssl, "ssl")
		set(&b.SslCertificate, "ssl_certificate")
		set(&b.DbServerName, "db_server_name")
		set(&b.SkipServerNameValidation, "skip_server_name_validation")
		set(&b.EnableMtls, "enable_mtls")
		set(&b.ClientCertificate, "client_certificate")
		set(&b.ClientPrivateKey, "client_private_key")
		set(&b.RotateOnUnlock, "rotate_on_unlock")
		set(&b.LockOnRead, "lock_on_read")
		set(&b.LockTtl, "lock_ttl")
		set(&b.Key, "key")
		set(&b.Description, "description")
		set(&b.MaxVersions, "max_versions")
		set(&b.DeleteProtection, "delete_protection")
		body = b
	}
	var err error
	if update {
		_, resp, e := client.TargetUpdateAerospike(ctx).Body(body.(akeyless_api.TargetUpdateAerospike)).Execute()
		err = common.HandleError("can't update target", resp, e)
	} else {
		_, resp, e := client.TargetCreateAerospike(ctx).Body(body.(akeyless_api.TargetCreateAerospike)).Execute()
		err = common.HandleError("can't create target", resp, e)
		if err == nil && d.Get("keep_prev_version").(string) != "" {
			updateBody := akeyless_api.TargetUpdateAerospike{Name: name, Token: &token}
			set(&updateBody.KeepPrevVersion, "keep_prev_version")
			_, resp, e = client.TargetUpdateAerospike(ctx).Body(updateBody).Execute()
			err = common.HandleError("can't update target", resp, e)
		}
	}
	if err != nil {
		return err
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
