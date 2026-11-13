terraform {
  required_providers {
    reversedock = {
      source = "Docker-Hunterpedia/reversedock"
    }
  }
}

# Every setting can come from the environment instead: RDOCK_ADMIN_URL and RDOCK_ADMIN_TOKEN
# (the token variable is the one `rdock` itself reads). Create a token with
# `rdock tokens create terraform --role operator --days 90` on the server.
provider "reversedock" {
  endpoint = "https://rdock.example.com:2080"
  token    = var.rdock_token

  # Only when the admin listener's certificate is signed by your own CA. There is no option
  # to skip certificate verification.
  # ca_cert_file = "/etc/ssl/internal-ca.pem"

  # Optional: request time limit, retries after 412, dry run during plan.
  # timeout          = "30s"
  # conflict_retries = 5
  # validate_on_plan = false
}

variable "rdock_token" {
  type      = string
  sensitive = true
}
