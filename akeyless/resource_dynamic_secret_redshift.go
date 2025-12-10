// generated fule
package akeyless

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	akeyless_api "github.com/akeylesslabs/akeyless-go"
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless/common"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceDynamicSecretRedshift() *schema.Resource {
	return &schema.Resource{
		Description: "Redshift dynamic secret resource",
		Create:      resourceDynamicSecretRedshiftCreate,
		Read:        resourceDynamicSecretRedshiftRead,
		Update:      resourceDynamicSecretRedshiftUpdate,
		Delete:      resourceDynamicSecretRedshiftDelete,
		Importer: &schema.ResourceImporter{
			State: resourceDynamicSecretRedshiftImport,
		},
		Schema: map[string]*schema.Schema{
			"name": {
				Type:        schema.TypeString,
				Required:    true,
				Description: "Dynamic Secret name",
				ForceNew:    true,
			},
			"target_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Name of existing target to use in dynamic secret creation",
			},
			"redshift_db_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Redshift DB name",
			},
			"redshift_username": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "redshiftL user",
			},
			"redshift_password": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Redshift password",
			},
			"redshift_host": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Redshift host name",
				Default:     "127.0.0.1",
			},
			"redshift_port": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Redshift port",
				Default:     "5439",
			},
			"creation_statements": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Redshift Creation Statements",
				Default:     "CREATE USER \"{{username}}\" WITH PASSWORD '{{password}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{username}}\";",
			},
			"ssl": {
				Type:        schema.TypeBool,
				Optional:    true,
				Description: "Enable/Disable SSL [true/false]",
				Default:     "false",
			},
			"user_ttl": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "User TTL",
				Default:     "60m",
			},
			"password_length": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "The length of the password to be generated",
			},
			"encryption_key_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Encrypt dynamic secret details with following key",
			},
			"custom_username_template": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Customize how temporary usernames are generated using go template",
			},
			"tags": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "List of the tags attached to this secret. To specify multiple tags use argument multiple times: -t Tag1 -t Tag2",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_enable": {
				Type:        schema.TypeString,
				Optional:    true,
				Description: "Enable/Disable secure remote access, [true/false]",
			},
			"secure_access_host": {
				Type:        schema.TypeSet,
				Optional:    true,
				Description: "Target DB servers for connections., For multiple values repeat this flag.",
				Elem:        &schema.Schema{Type: schema.TypeString},
			},
			"secure_access_web": {
				Type:        schema.TypeBool,
				Optional:    true,
				Computed:    true,
				Description: "Enable Web Secure Remote Access",
			},
			"secure_access_db_name": {
				Type:        schema.TypeString,
				Optional:    true,
				Computed:    true,
				Description: "The DB Name",
			},
		},
	}
}

func resourceDynamicSecretRedshiftCreate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	redshiftDbName := d.Get("redshift_db_name").(string)
	redshiftUsername := d.Get("redshift_username").(string)
	redshiftPassword := d.Get("redshift_password").(string)
	redshiftHost := d.Get("redshift_host").(string)
	redshiftPort := d.Get("redshift_port").(string)
	creationStatements := d.Get("creation_statements").(string)
	ssl := d.Get("ssl").(bool)
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKey := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless_api.DynamicSecretCreateRedshift{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.RedshiftDbName, redshiftDbName)
	common.GetAkeylessPtr(&body.RedshiftUsername, redshiftUsername)
	common.GetAkeylessPtr(&body.RedshiftPassword, redshiftPassword)
	common.GetAkeylessPtr(&body.RedshiftHost, redshiftHost)
	common.GetAkeylessPtr(&body.RedshiftPort, redshiftPort)
	common.GetAkeylessPtr(&body.CreationStatements, creationStatements)
	common.GetAkeylessPtr(&body.Ssl, ssl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKey, producerEncryptionKey)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.Tags, tags)

	_, _, err := client.DynamicSecretCreateRedshift(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't create Secret: %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't create Secret: %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretRedshiftRead(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()

	path := d.Id()

	body := akeyless_api.DynamicSecretGet{
		Name:  path,
		Token: &token,
	}

	rOut, res, err := client.DynamicSecretGet(ctx).Body(body).Execute()
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
	if rOut.UserTtl != nil {
		err = d.Set("user_ttl", *rOut.UserTtl)
		if err != nil {
			return err
		}
	}
	if rOut.Tags != nil {
		err = d.Set("tags", rOut.Tags)
		if err != nil {
			return err
		}
	}

	if rOut.ItemTargetsAssoc != nil {
		targetName := common.GetTargetName(rOut.ItemTargetsAssoc)
		err = common.SetDataByPrefixSlash(d, "target_name", targetName, d.Get("target_name").(string))
		if err != nil {
			return err
		}
	}
	if rOut.DbName != nil {
		err = d.Set("redshift_db_name", *rOut.DbName)
		if err != nil {
			return err
		}
	}
	if rOut.DbUserName != nil {
		err = d.Set("redshift_username", *rOut.DbUserName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPwd != nil {
		err = d.Set("redshift_password", *rOut.DbPwd)
		if err != nil {
			return err
		}
	}
	if rOut.DbHostName != nil {
		err = d.Set("redshift_host", *rOut.DbHostName)
		if err != nil {
			return err
		}
	}
	if rOut.DbPort != nil {
		err = d.Set("redshift_port", *rOut.DbPort)
		if err != nil {
			return err
		}
	}
	if rOut.RedshiftCreationStatements != nil {
		err = d.Set("creation_statements", *rOut.RedshiftCreationStatements)
		if err != nil {
			return err
		}
	}
	if rOut.SslConnectionMode != nil {
		err = d.Set("ssl", *rOut.SslConnectionMode)
		if err != nil {
			return err
		}
	}
	if rOut.DynamicSecretKey != nil {
		err = common.SetDataByPrefixSlash(d, "encryption_key_name", *rOut.DynamicSecretKey, d.Get("encryption_key_name").(string))
		if err != nil {
			return err
		}
	}

	if rOut.UsernameTemplate != nil {
		err = d.Set("custom_username_template", *rOut.UsernameTemplate)
		if err != nil {
			return err
		}
	}

	common.GetSra(d, rOut.SecureRemoteAccessDetails, "DYNAMIC_SECERT")

	d.SetId(path)

	return nil
}

func resourceDynamicSecretRedshiftUpdate(d *schema.ResourceData, m interface{}) error {
	provider := m.(*providerMeta)
	client := *provider.client
	token := *provider.token

	var apiErr akeyless_api.GenericOpenAPIError
	ctx := context.Background()
	name := d.Get("name").(string)
	targetName := d.Get("target_name").(string)
	redshiftDbName := d.Get("redshift_db_name").(string)
	redshiftUsername := d.Get("redshift_username").(string)
	redshiftPassword := d.Get("redshift_password").(string)
	redshiftHost := d.Get("redshift_host").(string)
	redshiftPort := d.Get("redshift_port").(string)
	creationStatements := d.Get("creation_statements").(string)
	ssl := d.Get("ssl").(bool)
	passwordLength := d.Get("password_length").(string)
	producerEncryptionKey := d.Get("encryption_key_name").(string)
	userTtl := d.Get("user_ttl").(string)
	customUsernameTemplate := d.Get("custom_username_template").(string)
	secureAccessEnable := d.Get("secure_access_enable").(string)
	secureAccessHostSet := d.Get("secure_access_host").(*schema.Set)
	secureAccessHost := common.ExpandStringList(secureAccessHostSet.List())
	tagsSet := d.Get("tags").(*schema.Set)
	tags := common.ExpandStringList(tagsSet.List())

	body := akeyless_api.DynamicSecretUpdateRedshift{
		Name:  name,
		Token: &token,
	}
	common.GetAkeylessPtr(&body.TargetName, targetName)
	common.GetAkeylessPtr(&body.RedshiftDbName, redshiftDbName)
	common.GetAkeylessPtr(&body.RedshiftUsername, redshiftUsername)
	common.GetAkeylessPtr(&body.RedshiftPassword, redshiftPassword)
	common.GetAkeylessPtr(&body.RedshiftHost, redshiftHost)
	common.GetAkeylessPtr(&body.RedshiftPort, redshiftPort)
	common.GetAkeylessPtr(&body.CreationStatements, creationStatements)
	common.GetAkeylessPtr(&body.Ssl, ssl)
	common.GetAkeylessPtr(&body.ProducerEncryptionKey, producerEncryptionKey)
	common.GetAkeylessPtr(&body.UserTtl, userTtl)
	common.GetAkeylessPtr(&body.PasswordLength, passwordLength)
	common.GetAkeylessPtr(&body.CustomUsernameTemplate, customUsernameTemplate)
	common.GetAkeylessPtr(&body.SecureAccessEnable, secureAccessEnable)
	common.GetAkeylessPtr(&body.SecureAccessHost, secureAccessHost)
	common.GetAkeylessPtr(&body.Tags, tags)

	_, _, err := client.DynamicSecretUpdateRedshift(ctx).Body(body).Execute()
	if err != nil {
		if errors.As(err, &apiErr) {
			return fmt.Errorf("can't update : %v", string(apiErr.Body()))
		}
		return fmt.Errorf("can't update : %v", err)
	}

	d.SetId(name)

	return nil
}

func resourceDynamicSecretRedshiftDelete(d *schema.ResourceData, m interface{}) error {
	return resourceDynamicSecretDelete(d, m)
}

func resourceDynamicSecretRedshiftImport(d *schema.ResourceData, m interface{}) ([]*schema.ResourceData, error) {

	id := d.Id()

	err := resourceDynamicSecretRedshiftRead(d, m)
	if err != nil {
		return nil, err
	}

	err = d.Set("name", id)
	if err != nil {
		return nil, err
	}

	return []*schema.ResourceData{d}, nil
}
