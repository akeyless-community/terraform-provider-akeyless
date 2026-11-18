package testutils

import (
	"context"
	"fmt"

	fwprovider "github.com/akeylesslabs/terraform-provider-akeyless/internal/framework"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/resource"
	"github.com/hashicorp/terraform-plugin-sdk/v2/terraform"
)

// NewMuxProtoV6ProviderFactories returns the SDK+Framework test provider.
func NewMuxProtoV6ProviderFactories() map[string]func() (tfprotov6.ProviderServer, error) {
	return map[string]func() (tfprotov6.ProviderServer, error){
		"akeyless": func() (tfprotov6.ProviderServer, error) {
			providerServer, err := fwprovider.NewMuxServer(context.Background())
			if err != nil {
				return nil, err
			}
			return providerServer(), nil
		},
	}
}

// CheckSecretNotInState accepts omitted or empty secret attributes.
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
