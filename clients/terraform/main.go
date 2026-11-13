// Command terraform-provider-reversedock is the Terraform and OpenTofu provider for
// ReverseDock's admin API. See README.md.
package main

import (
	"context"
	"flag"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/Docker-Hunterpedia/terraform-provider-reversedock/internal/provider"
)

// version is set by GoReleaser (-ldflags "-X main.version=…").
var version = "dev"

// The registry address is registry.terraform.io/<owner>/reversedock; the owner is the
// GitHub account or organisation that publishes the repository.
const address = "registry.terraform.io/Docker-Hunterpedia/reversedock"

func main() {
	var debug bool
	flag.BoolVar(&debug, "debug", false, "run the provider with support for debuggers such as delve")
	flag.Parse()

	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: address,
		Debug:   debug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
