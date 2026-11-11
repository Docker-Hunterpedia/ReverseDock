# Bring an object that was created in the dashboard or with curl under Terraform's control.
# Only objects owned by the API can be imported (`rdock`'s `GET /api/v1/config` shows the
# owner of each one); objects from the configuration file, Docker, Swarm or Kubernetes
# cannot be changed through the API.
terraform {
  required_providers {
    reversedock = {
      source = "Docker-Hunterpedia/reversedock"
    }
  }
}

provider "reversedock" {}

# Terraform 1.5+ and OpenTofu 1.6+: an import block, planned like any other change.
import {
  to = reversedock_service.legacy
  id = "legacy"
}

# Write the spec you want. The first apply after an import replaces the object with this
# spec (the imported state holds the server's own rendering, with every default filled in).
resource "reversedock_service" "legacy" {
  name = "legacy"
  spec = jsonencode({
    backends = [{ address = "10.0.0.9:8080" }]
  })
}

# With the CLI instead:
#   terraform import reversedock_service.legacy legacy
