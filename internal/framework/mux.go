package framework

import (
	"context"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-mux/tf5to6server"
	"github.com/hashicorp/terraform-plugin-mux/tf6muxserver"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// NewMuxServer serves the SDK v2 provider (upgraded from protocol v5 to v6)
// and the Framework provider as one provider. The SDK server must be listed
// first: it configures first, so the Framework ephemeral resources can reuse
// its authenticated client.
func NewMuxServer(ctx context.Context) (func() tfprotov6.ProviderServer, error) {
	sdkProvider := akeyless.Provider()
	upgradedSdkServer, err := tf5to6server.UpgradeServer(ctx, func() tfprotov5.ProviderServer {
		return schema.NewGRPCProviderServer(sdkProvider)
	})
	if err != nil {
		return nil, err
	}

	muxServer, err := tf6muxserver.NewMuxServer(ctx,
		func() tfprotov6.ProviderServer { return upgradedSdkServer },
		providerserver.NewProtocol6(New(sdkProvider)),
	)
	if err != nil {
		return nil, err
	}
	return muxServer.ProviderServer, nil
}
