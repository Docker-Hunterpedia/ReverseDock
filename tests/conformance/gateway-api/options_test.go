//go:build conformance

package gatewayapi

import (
	"os"
	"testing"

	"sigs.k8s.io/gateway-api/conformance/utils/suite"
	"sigs.k8s.io/yaml"
)

// TestOptionsFile needs no cluster. It loads options.yaml the strict way, so a misspelled key
// (which the upstream loader would silently ignore) fails here, in seconds, instead of after a
// 30 minute run with the wrong settings. run.sh runs it first.
func TestOptionsFile(t *testing.T) {
	data, err := os.ReadFile("options.yaml")
	if err != nil {
		t.Fatalf("read options.yaml: %v", err)
	}
	var opts suite.ConfigurableOptions
	if err := yaml.UnmarshalStrict(data, &opts); err != nil {
		t.Fatalf("options.yaml does not match suite.ConfigurableOptions: %v", err)
	}

	if opts.GatewayClassName != "reversedock" {
		t.Errorf("gatewayClassName = %q, want reversedock (the GatewayClass the chart creates)", opts.GatewayClassName)
	}

	known := map[suite.ConformanceProfileName]bool{
		suite.GatewayHTTPConformanceProfileName: true,
		suite.GatewayGRPCConformanceProfileName: true,
		suite.GatewayTLSConformanceProfileName:  true,
		suite.GatewayTCPConformanceProfileName:  true,
		suite.GatewayUDPConformanceProfileName:  true,
	}
	if len(opts.ConformanceProfiles) == 0 {
		t.Error("conformanceProfiles is empty: the suite would then derive the profiles from the supported features")
	}
	for _, p := range opts.ConformanceProfiles {
		if !known[p] {
			t.Errorf("conformanceProfiles: %q is not a Gateway profile of the suite", p)
		}
	}

	// Features must come from GatewayClass.status.supportedFeatures, never from this file.
	if len(opts.SupportedFeatures) != 0 || len(opts.ExemptFeatures) != 0 || opts.EnableAllSupportedFeatures {
		t.Error("supportedFeatures, exemptFeatures and enableAllSupportedFeatures must stay unset: features are inferred from the GatewayClass status")
	}

	// version is the only implementation field run.sh fills in; the others must be real.
	impl := opts.Implementation
	impl.Version = "placeholder"
	if err := impl.Validate(); err != nil {
		t.Errorf("implementation block: %v", err)
	}
}
