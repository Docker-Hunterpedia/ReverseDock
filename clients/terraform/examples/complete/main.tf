# A service, a middleware and a route that uses both: the whole of a small site.
# Run `terraform init && terraform apply` with RDOCK_ADMIN_URL and RDOCK_ADMIN_TOKEN set
# (a token with the operator role).
terraform {
  required_providers {
    reversedock = {
      source = "Docker-Hunterpedia/reversedock"
    }
  }
}

provider "reversedock" {}

resource "reversedock_service" "shop" {
  name = "shop"
  spec = jsonencode({
    backends = [{ address = "10.0.0.5:8080" }]
    health = {
      active = {
        path     = "/healthz"
        interval = "10s"
      }
    }
  })
}

resource "reversedock_middleware" "security_headers" {
  name = "security-headers"
  spec = jsonencode({
    type = "headers"
    response = {
      set = { "X-Content-Type-Options" = "nosniff" }
    }
  })
}

resource "reversedock_route" "shop" {
  name = "shop"
  spec = jsonencode({
    match       = "Host(`shop.example.com`) && PathPrefix(`/`)"
    service     = reversedock_service.shop.name
    middlewares = [reversedock_middleware.security_headers.name]
  })
}

# The references above are expressions, so Terraform creates the service and the middleware
# first and deletes them last. The admin API refuses to delete an object something still
# refers to, and says which one.
output "route_etag" {
  value = reversedock_route.shop.etag
}
