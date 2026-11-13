data "reversedock_status" "this" {}

output "rdock_version" {
  value = data.reversedock_status.this.version
}
