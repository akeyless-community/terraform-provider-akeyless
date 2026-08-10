package main

import (
	"context"
	"flag"
	"log"

	"github.com/akeylesslabs/terraform-provider-akeyless/akeyless"
	fwprovider "github.com/akeylesslabs/terraform-provider-akeyless/internal/framework"
	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov5"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6/tf6server"
	"github.com/hashicorp/terraform-plugin-mux/tf5to6server"
	"github.com/hashicorp/terraform-plugin-mux/tf6muxserver"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

// Generate docs for website
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	ctx := context.Background()

	sdkProvider := akeyless.Provider()
	upgradedSdkServer, err := tf5to6server.UpgradeServer(ctx, func() tfprotov5.ProviderServer {
		return schema.NewGRPCProviderServer(sdkProvider)
	})
	if err != nil {
		log.Fatal(err)
	}

	providers := []func() tfprotov6.ProviderServer{
		func() tfprotov6.ProviderServer { return upgradedSdkServer },
		providerserver.NewProtocol6(fwprovider.New(sdkProvider)),
	}

	muxServer, err := tf6muxserver.NewMuxServer(ctx, providers...)
	if err != nil {
		log.Fatal(err)
	}

	var serveOpts []tf6server.ServeOpt
	if debug {
		serveOpts = append(serveOpts, tf6server.WithManagedDebug())
	}

	err = tf6server.Serve(
		"registry.terraform.io/akeyless-community/akeyless",
		muxServer.ProviderServer,
		serveOpts...,
	)
	if err != nil {
		log.Fatal(err)
	}
}
