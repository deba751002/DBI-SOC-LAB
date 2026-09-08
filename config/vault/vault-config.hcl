# HashiCorp Vault — lab config (file storage backend, no TLS).
# For production: swap the "file" backend for "raft" (clustered) or a cloud
# KMS auto-unseal, and put a real TLS cert on the listener instead of tls_disable.

storage "file" {
  path = "/vault/file"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = "true"   # nginx/Keycloak should terminate TLS in front of this in prod
}

api_addr     = "http://0.0.0.0:8200"
ui           = true
disable_mlock = false
