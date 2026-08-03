package ephemeral

import (
	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/ephemeral"
)

func clientFrom(req ephemeral.ConfigureRequest, diags *diag.Diagnostics) *akeyless.ApiClient {
	if req.ProviderData == nil {
		return nil
	}
	c, ok := req.ProviderData.(*akeyless.ApiClient)
	if !ok {
		diags.AddError("Unexpected provider data", "Expected *akeyless.ApiClient")
		return nil
	}
	return c
}

func requireClient(c *akeyless.ApiClient, diags *diag.Diagnostics) bool {
	if c == nil {
		diags.AddError("Provider not configured", "Akeyless client is not available; check provider authentication")
		return false
	}
	return true
}
