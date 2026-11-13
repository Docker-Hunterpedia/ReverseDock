package main

// Generate the documentation in docs/ from the schema, examples/ and templates/. Needs a
// terraform or tofu binary on PATH (tfplugindocs asks it for the provider schema).
//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs@v0.25.0 generate --provider-name reversedock --rendered-provider-name ReverseDock
