# Production prerequisites

The production overlay uses an externally operated, highly available TiDB
deployment. It intentionally removes the development-only UniStore StatefulSet
and its initialization Jobs.

Before rollout, create `ssl-proxy-prod-tidb-endpoint` in the
`prod-ssl-proxy` namespace with these non-secret keys:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: ssl-proxy-prod-tidb-endpoint
  namespace: prod-ssl-proxy
data:
  TIDB_HOST: tidb.example.internal
  TIDB_PORT: "4000"
  TIDB_TLS_SERVER_NAME: tidb.example.internal
  SCHEMA_MIGRATOR_TIDB_JDBC_URL: jdbc:mysql://tidb.example.internal:4000/schema_migrator?sslMode=VERIFY_IDENTITY&trustCertificateKeyStoreUrl=file:///run/tidb-tls/truststore.p12&trustCertificateKeyStoreType=PKCS12&trustCertificateKeyStorePassword=changeit&fallbackToSystemTrustStore=false&connectionTimeZone=UTC&forceConnectionTimeZoneToSession=true
```

Provision the existing TiDB account Secrets and `tidb-client-ca` for that
endpoint before sync. Production release approval also requires tested TiDB
backup, restore, failover, and recovery procedures with recorded RTO and RPO.
