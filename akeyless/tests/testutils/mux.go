package testutils

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	fwprovider "github.com/akeylesslabs/terraform-provider-akeyless/internal/framework"
	"github.com/hashicorp/go-version"
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

// SkipIfTerraformBelow skips when the local terraform CLI is older than min (e.g. "1.11.0").
func SkipIfTerraformBelow(t *testing.T, min string) {
	t.Helper()
	out, err := exec.Command("terraform", "version", "-json").Output()
	if err != nil {
		t.Skipf("skipping: terraform version unavailable: %v", err)
	}
	var info struct {
		TerraformVersion string `json:"terraform_version"`
	}
	if err := json.Unmarshal(out, &info); err != nil {
		t.Skipf("skipping: parse terraform version: %v", err)
	}
	cur, err := version.NewVersion(info.TerraformVersion)
	if err != nil {
		t.Skipf("skipping: invalid terraform version %q: %v", info.TerraformVersion, err)
	}
	want, err := version.NewVersion(min)
	if err != nil {
		t.Fatalf("invalid min version %q: %v", min, err)
	}
	if cur.LessThan(want) {
		t.Skipf("skipping: needs Terraform >= %s (have %s)", min, info.TerraformVersion)
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
