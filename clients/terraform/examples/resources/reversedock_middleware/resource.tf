resource "reversedock_middleware" "security_headers" {
  name = "security-headers"
  spec = jsonencode({
    type = "headers"
    response = {
      set = {
        "X-Content-Type-Options" = "nosniff"
        "Referrer-Policy"        = "strict-origin-when-cross-origin"
      }
    }
  })
}
