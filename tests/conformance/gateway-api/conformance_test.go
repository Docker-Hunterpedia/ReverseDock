//go:build conformance

// Package gatewayapi runs the upstream Gateway API conformance suite against ReverseDock.
//
// The build tag keeps this file out of every ordinary `go vet ./...` and `go test ./...`: the
// suite needs a cluster and a Go 1.27 toolchain. Run it through run.sh (README.md), or by hand:
//
//	go test -tags conformance -timeout 40m -run TestConformance ./... -args \
//	    --conformance-options-file options.yaml --version v0.7.0 --report-output report.yaml
//
// Everything that configures the run (gateway class, profiles, implementation block, skipped
// tests) lives in options.yaml; the flags after -args override it, which is how run.sh sets the
// version and the report path.
package gatewayapi

import (
	"testing"

	"sigs.k8s.io/gateway-api/conformance"
	"sigs.k8s.io/gateway-api/conformance/utils/flags"
)

// TestConformance is the upstream suite, unmodified: conformance.RunConformance parses the
// options file named by --conformance-options-file (YAML keys are the json tags of
// suite.ConfigurableOptions), applies explicitly set flags on top, infers the supported features
// from GatewayClass.status.supportedFeatures and writes the report to the --report-output path.
func TestConformance(t *testing.T) {
	if *flags.ConformanceOptionsFile == "" {
		t.Fatal("pass --conformance-options-file (see README.md); running the suite with upstream defaults would test the wrong GatewayClass and write no report")
	}
	conformance.RunConformance(t)
}
