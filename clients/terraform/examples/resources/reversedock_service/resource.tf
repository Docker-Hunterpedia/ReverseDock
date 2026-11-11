resource "reversedock_service" "shop" {
  name = "shop"
  spec = jsonencode({
    backends = [
      { address = "10.0.0.5:8080" },
      { address = "10.0.0.6:8080" },
    ]
  })
}
