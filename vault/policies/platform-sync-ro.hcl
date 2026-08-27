# Platform sync read-only policy
# Grants read access to all secrets under secret/ssl-proxy/prod/ and permits
# the periodic service token to inspect and renew itself.

path "secret/data/ssl-proxy/prod/*" {
  capabilities = ["read"]
}

path "secret/metadata/ssl-proxy/prod/*" {
  capabilities = ["read"]
}

path "auth/token/lookup-self" {
  capabilities = ["read"]
}

path "auth/token/renew-self" {
  capabilities = ["update"]
}
