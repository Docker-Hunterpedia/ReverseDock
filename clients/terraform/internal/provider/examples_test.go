package provider

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hashicorp/hcl/v2/hclparse"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

// TestExamplesParseAndUseRealSchemas loads every .tf file under examples/ with the HCL
// parser (no CLI needed) and checks that each resource, data source and provider attribute
// they use exists in the provider's schema. Against a CLI, `terraform validate` on
// examples/complete runs in CI (see README).
func TestExamplesParseAndUseRealSchemas(t *testing.T) {
	root := filepath.Join("..", "..", "examples")
	resp, err := newServer(t).GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	attrs := func(b *tfprotov6.SchemaBlock) map[string]bool {
		out := map[string]bool{}
		for _, a := range b.Attributes {
			out[a.Name] = true
		}
		return out
	}

	parser := hclparse.NewParser()
	files := 0
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".tf") {
			return err
		}
		files++
		src, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		f, diags := parser.ParseHCL(src, path)
		if diags.HasErrors() {
			t.Errorf("%s: %s", path, diags.Error())
			return nil
		}
		body, ok := f.Body.(*hclsyntax.Body)
		if !ok {
			t.Errorf("%s: not native syntax", path)
			return nil
		}
		for _, blk := range body.Blocks {
			var schema *tfprotov6.Schema
			switch blk.Type {
			case "resource":
				schema = resp.ResourceSchemas[blk.Labels[0]]
			case "data":
				schema = resp.DataSourceSchemas[blk.Labels[0]]
			case "provider":
				if blk.Labels[0] == "reversedock" {
					schema = resp.Provider
				}
			default:
				continue
			}
			if schema == nil {
				if blk.Type == "provider" {
					continue // another provider in the example
				}
				t.Errorf("%s: %s %q is not in the provider", path, blk.Type, blk.Labels[0])
				continue
			}
			known := attrs(schema.Block)
			for name := range blk.Body.Attributes {
				switch name {
				case "depends_on", "count", "for_each", "provider", "lifecycle":
				default:
					if !known[name] {
						t.Errorf("%s: %s %q has no attribute %q", path, blk.Type, blk.Labels[0], name)
					}
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if files == 0 {
		t.Fatal("no examples found")
	}
}
