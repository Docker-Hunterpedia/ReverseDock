resource "reversedock_route" "shop" {
  name = "shop"
  spec = jsonencode({
    match       = "Host(`shop.example.com`)"
    service     = reversedock_service.shop.name
    middlewares = [reversedock_middleware.security_headers.name]
  })
}
