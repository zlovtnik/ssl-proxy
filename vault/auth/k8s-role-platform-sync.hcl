# Vault Kubernetes auth role for platform-sync
# Binds the ssl-proxy-platform-sync ServiceAccount in prod-ssl-proxy namespace
# to the platform-sync-ro policy with a 1-hour TTL

# This file documents the expected Vault configuration.
# Run bootstrap-vault-platform-sync.sh to apply it.

# Role configuration:
# - role_name: platform-sync
# - bound_service_account_names: ssl-proxy-platform-sync
# - bound_service_account_namespaces: prod-ssl-proxy
# - policies: platform-sync-ro
# - ttl: 1h
# - max_ttl: 1h
