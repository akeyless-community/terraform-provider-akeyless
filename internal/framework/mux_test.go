package framework

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// The SDK v2 and Framework providers must declare the same provider config schema,
// otherwise Terraform cannot load the muxed provider at all.
func TestMuxServerProviderSchemasMatch(t *testing.T) {
	ctx := context.Background()
	server, err := NewMuxServer(ctx)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := server().GetProviderSchema(ctx, &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range resp.Diagnostics {
		if d.Severity == tfprotov6.DiagnosticSeverityError {
			t.Fatalf("%s: %s", d.Summary, d.Detail)
		}
	}
}
