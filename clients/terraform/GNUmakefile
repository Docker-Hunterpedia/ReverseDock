# Targets for the ReverseDock Terraform/OpenTofu provider. Run from clients/terraform.
#
#   make build          build ./terraform-provider-reversedock
#   make test           unit tests (no Terraform or OpenTofu binary needed)
#   make testacc        the same tests plus the CLI-driven tests (TF_ACC=1); needs `terraform` or
#                       `tofu` (TF_ACC_TERRAFORM_PATH). Against the in-process fake admin API, or,
#                       with RDOCK_ADMIN_URL and RDOCK_ADMIN_TOKEN set, against a running rdock
#                       started with testdata/rdock.yaml.
#   make docs           regenerate docs/ with tfplugindocs (needs terraform or tofu on PATH)
#   make check          what CI runs: vet, gofmt, tidy, unit tests, docs up to date
export GOTOOLCHAIN ?= auto

GO ?= go

.PHONY: build test testacc fmt vet lint tidy docs check

build:
	$(GO) build -trimpath -o terraform-provider-reversedock .

test:
	$(GO) test ./... -count=1

testacc:
	TF_ACC=1 $(GO) test ./... -count=1 -timeout 20m

fmt:
	gofmt -w .

vet:
	$(GO) vet ./...

lint:
	golangci-lint run ./...

tidy:
	$(GO) mod tidy

docs:
	$(GO) generate ./...

check: vet
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt needed"; exit 1; }
	$(GO) mod tidy
	git diff --exit-code -- go.mod go.sum
	$(GO) test ./... -count=1
	$(GO) generate ./...
	git diff --exit-code -- docs
