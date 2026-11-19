package main

import (
	"context"
	"log"

	fwprovider "github.com/akeylesslabs/terraform-provider-akeyless/internal/framework"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6/tf6server"
)

// Generate docs for website
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.25.0

func main() {
	providerServer, err := fwprovider.NewMuxServer(context.Background())
	if err != nil {
		log.Fatal(err)
	}

	err = tf6server.Serve(
		"registry.terraform.io/akeyless-community/akeyless",
		providerServer,
	)
	if err != nil {
		log.Fatal(err)
	}
}