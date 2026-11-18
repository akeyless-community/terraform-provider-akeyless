package main_test

import (
	"context"
	"testing"

	fwprovider "github.com/akeylesslabs/terraform-provider-akeyless/internal/framework"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

func TestMuxServerSchemaParity(t *testing.T) {
	ctx := context.Background()
	providerServer, err := fwprovider.NewMuxServer(ctx)
	if err != nil {
		t.Fatalf("mux server: %v", err)
	}
	resp, err := providerServer().GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatalf("provider schema: %v", err)
	}
	for _, diagnostic := range resp.Diagnostics {
		if diagnostic.Severity == tfprotov6.DiagnosticSeverityError {
			t.Fatalf("provider schema diagnostic: %s", diagnostic.Summary)
		}
	}
}
