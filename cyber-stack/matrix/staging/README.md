# Staging prerequisites

Staging is a full deployment on its dedicated cluster in `staging-ssl-proxy`.
The platform must provision `sync_staging`, TLS, least-privilege PostgreSQL
accounts, registry access, a Cloudflare tunnel, and certificates for
`staging-gateway.rclabs.uk`, `staging-migrator.rclabs.uk`, and
`staging-search.rclabs.uk`.

Before registering the staging Applications, materialize all Vault inputs at
`secret/ssl-proxy/staging` and the non-secret
`ssl-proxy-staging-postgres-endpoint` ConfigMap. Exact endpoint and tunnel
values are platform supplied and intentionally not committed.
