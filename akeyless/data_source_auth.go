package akeyless

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func dataSourceAuth() *schema.Resource {
	return &schema.Resource{
		Description: "Authenticate to Akeyless and returns a token to be used by the provider",
		Read:        dataSourceAuthRead,
		Schema: map[string]*schema.Schema{
			"api_key_login":  apiKeyLoginSchema,
			"aws_iam_login":  awsIamLoginSchema,
			"gcp_login":      gcpLoginSchema,
			"azure_ad_login": azureAdLoginSchema,
			"jwt_login":      jwtLoginSchema,
			"email_login":    emailLoginSchema,
			"uid_login":      uidLoginSchema,
			"cert_login":     certLoginSchema,
			"token": {
				Type:        schema.TypeString,
				Computed:    true,
				Sensitive:   true,
				Description: "The token",
			},
			"complete_auth_link": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Complete authentication link",
			},
			"expiration": {
				Type:        schema.TypeString,
				Computed:    true,
				Description: "Token expiration time",
			},
		},
	}
}

func dataSourceAuthRead(d *schema.ResourceData, m interface{}) error {

	provider := m.(*providerMeta)
	client := *provider.client

	ctx := context.Background()

	authBody, err := getAuthInfo(d)
	if err != nil {
		return err
	}

	authOut, _, err := client.Auth(ctx).Body(*authBody).Execute()
	if err != nil {
		return err
	}

	token := authOut.GetToken()
	err = d.Set("token", token)
	if err != nil {
		return err
	}

	if authOut.CompleteAuthLink != nil {
		err = d.Set("complete_auth_link", authOut.GetCompleteAuthLink())
		if err != nil {
			return err
		}
	}

	if authOut.Expiration != nil {
		err = d.Set("expiration", authOut.GetExpiration())
		if err != nil {
			return err
		}
	}

	provider.token = &token

	d.SetId("dummy_id")
	return nil
}
