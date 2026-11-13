# OpenBao Agent: log in with AppRole and render one file. Static (non-leased) secrets such as
# KV v2 are rendered again every static_secret_render_interval (default 5m).
vault {
  address = "https://openbao.example.com:8200"
}

auto_auth {
  method "approle" {
    config = {
      role_id_file_path                   = "/etc/openbao/approle/role-id"
      secret_id_file_path                 = "/etc/openbao/approle/secret-id"
      remove_secret_id_file_after_reading = false
    }
  }
}

template_config {
  static_secret_render_interval = "5m"
}

template {
  source      = "/etc/openbao/backend-key.ctmpl"
  destination = "/rendered/backend-key"
  perms       = "0644"
}
