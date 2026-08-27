# Platform sync read-only policy
# Grants read access to all secrets under secret/ssl-proxy/prod/
# No write, delete, or list permissions on parent paths

path "secret/data/ssl-proxy/prod/*" {
  capabilities = ["read"]
}

path "secret/metadata/ssl-proxy/prod/*" {
  capabilities = ["read"]
}

# Deny access to everything else
path "sys/*" {
  capabilities = ["deny"]
}

path "auth/*" {
  capabilities = ["deny"]
}

path "identity/*" {
  capabilities = ["deny"]
}
