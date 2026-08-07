package testutils

import (
	"context"
	"fmt"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	fwprovider "github.com/akeylesslabs/terraform-provider-akeyless/internal/framework"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-mux/tf5to6server"
	"github.com/hashicorp/terraform-plugin-mux/tf6muxserver"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// NewMuxProtoV6ProviderFactories returns the muxed SDK+Framework provider
// used for ephemeral-resource acceptance tests.
func NewMuxProtoV6ProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"akeyless": func() (tfprotov6.ProviderServer, error) {
			ctx := context.Background()
			upgraded, err := tf5to6server.UpgradeServer(ctx, func() tfprotov5.ProviderServer {
				return schema.NewGRPCProviderServer(akeyless.Provider())
			})
			if err != nil {
				return nil, err
			}
			mux, err := tf6muxserver.NewMuxServer(ctx,
				func() tfprotov6.ProviderServer { return upgraded },
				providerserver.NewProtocol6(fwprovider.New()),
			)
			if err != nil {
				return nil, err
			}
			return mux.ProviderServer(), nil
		},
	}
}

// CheckSecretNotInState asserts that a sensitive attribute is not persisted
// as a usable secret value. Accepts both omitted and empty string, since TF
// 1.11+ may nullify cleared optional attributes after write-only Read().
func CheckSecretNotInState(addr, attr string) resource.TestCheckFunc {
	return func(s *terraform.State) error {
		rs, ok := s.RootModule().Resources[addr]
		if !ok {
			return fmt.Errorf("resource %s not found in state", addr)
		}
		if v, exists := rs.Primary.Attributes[attr]; exists && v != "" {
			return fmt.Errorf("%s.%s still present in state", addr, attr)
		}
		return nil
	}
}
