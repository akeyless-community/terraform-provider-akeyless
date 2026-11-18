package main

import (
	"context"
	"flag"
	"log"

	fwprovider "github.com/akeylesslabs/terraform-provider-akeyless/internal/framework"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6/tf6server"
)

// Generate docs for website
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	providerServer, err := fwprovider.NewMuxServer(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	var serveOpts []tf6server.ServeOpt
	if debug {
		serveOpts = append(serveOpts, tf6server.WithManagedDebug())
	}

	err = tf6server.Serve(
		"registry.terraform.io/akeyless-community/akeyless",
		providerServer,
		serveOpts...,
	)
	if err != nil {
		log.Fatal(err)
	}
}
