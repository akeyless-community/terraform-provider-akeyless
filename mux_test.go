package main_test

import (
	"context"
	"testing"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	fwprovider "github.com/akeylesslabs/terraform-provider-akeyless/internal/framework"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-mux/tf5to6server"
	"github.com/hashicorp/terraform-plugin-mux/tf6muxserver"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestMuxServerSchemaParity(t *testing.T) {
	ctx := context.Background()
	sdkProvider := akeyless.Provider()
	upgraded, err := tf5to6server.UpgradeServer(ctx, func() tfprotov5.ProviderServer {
		return schema.NewGRPCProviderServer(sdkProvider)
	})
	if err != nil {
		t.Fatalf("upgrade sdk server: %v", err)
	}
	mux, err := tf6muxserver.NewMuxServer(ctx,
		func() tfprotov6.ProviderServer { return upgraded },
		providerserver.NewProtocol6(fwprovider.New(sdkProvider)),
	)
	if err != nil {
		t.Fatalf("mux server: %v", err)
	}
	resp, err := mux.ProviderServer().GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("provider schema: %v", err)
	}
	for _, diagnostic := range resp.Diagnostics {
		if diagnostic.Severity == tfprotov6.DiagnosticSeverityError {
			t.Fatalf("provider schema diagnostic: %s", diagnostic.Summary)
		}
	}
}
