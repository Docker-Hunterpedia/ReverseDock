# A service from the configuration file or a provider, read-only here.
data "reversedock_service" "from_docker" {
  name = "whoami@docker"
}

output "backends" {
  value = jsondecode(data.reversedock_service.from_docker.spec).backends
}
