"""Tests for stackctl effective values generation."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from stackctl import (
    Component,
    StackConfig,
    deep_merge,
    generate_effective_values,
)


class TestDeepMerge:
    """Test deep merge utility."""

    def test_flat_merge(self):
        base = {"a": 1, "b": 2}
        override = {"b": 3, "c": 4}
        result = deep_merge(base, override)
        assert result == {"a": 1, "b": 3, "c": 4}

    def test_nested_merge(self):
        base = {"a": {"x": 1, "y": 2}, "b": 1}
        override = {"a": {"y": 3, "z": 4}}
        result = deep_merge(base, override)
        assert result == {"a": {"x": 1, "y": 3, "z": 4}, "b": 1}

    def test_deep_nested_merge(self):
        base = {"a": {"b": {"c": 1, "d": 2}}}
        override = {"a": {"b": {"d": 3, "e": 4}}}
        result = deep_merge(base, override)
        assert result == {"a": {"b": {"c": 1, "d": 3, "e": 4}}}

    def test_override_replaces_non_dict(self):
        base = {"a": [1, 2, 3]}
        override = {"a": "string"}
        result = deep_merge(base, override)
        assert result == {"a": "string"}

    def test_empty_base(self):
        result = deep_merge({}, {"a": 1})
        assert result == {"a": 1}

    def test_empty_override(self):
        base = {"a": 1}
        result = deep_merge(base, {})
        assert result == {"a": 1}

    def test_preserves_original(self):
        base = {"a": {"x": 1}}
        override = {"a": {"y": 2}}
        deep_merge(base, override)
        assert base == {"a": {"x": 1}}


class TestGenerateEffectiveValues:
    """Test effective values generation for components."""

    def _make_config(self) -> StackConfig:
        return StackConfig(
            version=1,
            components={
                "tidb": Component(
                    type="helm",
                    release="ssl-proxy-tidb",
                    chart="./helm/ssl-proxy/charts/tidb",
                    values_key="tidb",
                    include_global=True,
                    set={"external": False},
                ),
                "redis": Component(
                    type="helm",
                    release="ssl-proxy-redis",
                    chart="./helm/ssl-proxy/charts/redis-runtime",
                    values_key="redisRuntime",
                    include_global=True,
                ),
                "app": Component(
                    type="helm",
                    release="app",
                    chart="./charts/app",
                    values_key="app",
                    include_global=False,
                ),
            },
        )

    def test_tidb_values_extraction(self):
        config = self._make_config()
        umbrella_values = [
            {
                "global": {
                    "shared": {
                        "tidb": {"host": "example.com", "port": 4000},
                    }
                },
                "tidb": {
                    "external": True,
                    "minimumVersion": "8.5.0",
                },
            }
        ]

        effective = generate_effective_values(config, "tidb", umbrella_values)

        # Component values extracted
        assert effective["external"] is False  # overridden by set
        assert effective["minimumVersion"] == "8.5.0"

        # Global block included
        assert "global" in effective
        assert effective["global"]["shared"]["tidb"]["host"] == "example.com"

    def test_redis_values_with_global(self):
        config = self._make_config()
        umbrella_values = [
            {
                "global": {"shared": {"redis": {"host": "redis.local"}}},
                "redisRuntime": {"enabled": True},
            }
        ]

        effective = generate_effective_values(config, "redis", umbrella_values)

        assert effective["enabled"] is True
        assert effective["global"]["shared"]["redis"]["host"] == "redis.local"

    def test_component_without_global(self):
        config = self._make_config()
        umbrella_values = [
            {
                "global": {"shared": {"something": "value"}},
                "app": {"replicas": 3},
            }
        ]

        effective = generate_effective_values(config, "app", umbrella_values)

        assert effective["replicas"] == 3
        assert "global" not in effective

    def test_multiple_values_files_merged_in_order(self):
        config = self._make_config()
        umbrella_values = [
            {
                "global": {},
                "tidb": {"setting1": "from-first", "setting2": "from-first"},
            },
            {"tidb": {"setting2": "from-second", "setting3": "from-second"}},
        ]

        effective = generate_effective_values(config, "tidb", umbrella_values)

        assert effective["setting1"] == "from-first"
        assert effective["setting2"] == "from-second"  # second file wins
        assert effective["setting3"] == "from-second"

    def test_runtime_overrides_applied(self):
        config = self._make_config()
        umbrella_values = [{"global": {}, "tidb": {"setting": "original"}}]
        runtime = {
            "tidb": {"setting": "runtime-override", "extra": "value"},
        }

        effective = generate_effective_values(
            config, "tidb", umbrella_values, runtime_overrides=runtime
        )

        assert effective["setting"] == "runtime-override"
        assert effective["extra"] == "value"

    def test_component_set_overrides_applied(self):
        config = self._make_config()
        umbrella_values = [{"global": {}, "tidb": {"external": True}}]

        effective = generate_effective_values(config, "tidb", umbrella_values)

        # set: {external: false} from component config should override
        assert effective["external"] is False

    def test_empty_umbrella_values(self):
        config = self._make_config()
        umbrella_values = [{}]

        with pytest.raises(ValueError, match="values_key"):
            generate_effective_values(config, "tidb", umbrella_values)

    def test_missing_values_key_is_an_error(self):
        config = self._make_config()
        umbrella_values = [{"global": {"shared": {"tidb": {}}}}]

        with pytest.raises(ValueError, match="values_key"):
            generate_effective_values(config, "tidb", umbrella_values)


# ---------------------------------------------------------------------------
# Fixtures for subchart-defaults tests
# ---------------------------------------------------------------------------


def _write_yaml(path: Path, data: dict) -> None:
    """Write a dict as YAML to the given path, creating parent dirs."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w") as f:
        yaml.dump(data, f, default_flow_style=False)


@pytest.fixture()
def stack_root(tmp_path: Path) -> Path:
    """Create a minimal repo skeleton with subchart values.yaml files.

    Layout under tmp_path:
        helm/ssl-proxy/charts/tidb/values.yaml
        helm/ssl-proxy/charts/redis-runtime/values.yaml
        helm/ssl-proxy/charts/telemetry/values.yaml
        helm/ssl-proxy/charts/schema-migrator/values.yaml
        helm/ssl-proxy/charts/java-coordinator/values.yaml
        helm/ssl-proxy/charts/tidb-schema-executor/values.yaml
    """
    charts = tmp_path / "helm" / "ssl-proxy" / "charts"

    _write_yaml(
        charts / "tidb" / "values.yaml",
        {
            "external": True,
            "minimumVersion": "8.5.0",
            "egress": {"enabled": True, "cidrs": []},
            "image": {"repository": "pingcap/tidb", "tag": "v8.5.0"},
            "replicas": 1,
        },
    )

    _write_yaml(
        charts / "redis-runtime" / "values.yaml",
        {
            "enabled": True,
            "image": {"repository": "redis", "tag": "7.4.3-alpine"},
        },
    )

    _write_yaml(
        charts / "telemetry" / "values.yaml",
        {
            "enabled": False,
            "monitoring": {"enabled": True},
        },
    )

    _write_yaml(
        charts / "schema-migrator" / "values.yaml",
        {
            "enabled": False,
            "publicHostname": "",
            "traefik": {"acme": {"email": ""}},
        },
    )

    _write_yaml(
        charts / "java-coordinator" / "values.yaml",
        {
            "enabled": True,
            "tidb": {"sslMode": "VERIFY_IDENTITY"},
            "global": {
                "shared": {
                    "minio": {
                        "endpoint": "http://minio.minio.svc.cluster.local:9000",
                    },
                },
            },
        },
    )

    _write_yaml(
        charts / "tidb-schema-executor" / "values.yaml",
        {
            "enabled": False,
        },
    )

    return tmp_path


def _full_config() -> StackConfig:
    """Return a config matching the 11-component stack.yaml layout."""
    return StackConfig(
        version=1,
        components={
            "tidb": Component(
                type="helm",
                release="ssl-proxy-tidb",
                chart="./helm/ssl-proxy/charts/tidb",
                values_key="tidb",
                include_global=True,
                set={"external": False},
            ),
            "redpanda": Component(
                type="helm",
                release="ssl-proxy-redpanda",
                chart="./helm/ssl-proxy/charts/redpanda",
                values_key="redpanda",
                include_global=True,
            ),
            "minio": Component(
                type="helm",
                release="ssl-proxy-minio",
                chart="./helm/ssl-proxy/charts/minio",
                values_key="minio",
                include_global=True,
            ),
            "redis": Component(
                type="helm",
                release="ssl-proxy-redis",
                chart="./helm/ssl-proxy/charts/redis-runtime",
                values_key="redisRuntime",
                include_global=True,
            ),
            "telemetry": Component(
                type="helm",
                release="ssl-proxy-telemetry",
                chart="./helm/ssl-proxy/charts/telemetry",
                values_key="telemetry",
                include_global=True,
            ),
            "tidb-schema-executor": Component(
                type="helm-job",
                release="ssl-proxy-tidb-schema",
                chart="./helm/ssl-proxy/charts/tidb-schema-executor",
                values_key="tidbSchemaExecutor",
                include_global=True,
                job={"rerun": "replace"},
            ),
            "schema-migrator": Component(
                type="helm",
                release="ssl-proxy-schema-migrator",
                chart="./helm/ssl-proxy/charts/schema-migrator",
                values_key="schemaMigrator",
                include_global=True,
            ),
            "java-coordinator": Component(
                type="helm",
                release="ssl-proxy-coordinator",
                chart="./helm/ssl-proxy/charts/java-coordinator",
                values_key="javaCoordinator",
                include_global=True,
            ),
            "atheros-search": Component(
                type="helm",
                release="ssl-proxy-atheros-search",
                chart="./helm/ssl-proxy/charts/atheros-search",
                values_key="atherosSearch",
                include_global=True,
            ),
            "atheros-sensor": Component(
                type="helm",
                release="ssl-proxy-atheros-sensor",
                chart="./helm/ssl-proxy/charts/atheros-sensor",
                values_key="atherosSensor",
                include_global=True,
            ),
            "proxy": Component(
                type="helm",
                release="ssl-proxy-proxy",
                chart="./helm/ssl-proxy/charts/proxy",
                values_key="proxy",
                include_global=True,
            ),
        },
    )


# ---------------------------------------------------------------------------
# Spec-required test fixtures
# ---------------------------------------------------------------------------


class TestEffectiveValuesFromSpec:
    """Verify the exact scenarios from the Phase 3 spec."""

    def test_tidb_effective_from_spec_fixture(self, stack_root: Path):
        """Spec fixture: umbrella provides global.shared.tidb.host and
        tidb.external=false + tidb.minimumVersion. Verify the effective
        values file contains the merged result."""
        config = _full_config()
        umbrella_values = [
            {
                "global": {
                    "shared": {
                        "tidb": {"host": "example"},
                    },
                },
                "tidb": {
                    "external": False,
                    "minimumVersion": "8.5.0",
                },
            }
        ]

        effective = generate_effective_values(
            config,
            "tidb",
            umbrella_values,
            root_dir=stack_root,
        )

        # Effective files contain only umbrella overlays; Helm loads chart defaults.
        assert effective["external"] is False  # umbrella + set override
        assert effective["minimumVersion"] == "8.5.0"
        assert "egress" not in effective
        assert "replicas" not in effective

        # Global block from umbrella
        assert "global" in effective
        assert effective["global"]["shared"]["tidb"]["host"] == "example"

    def test_tidb_effective_file_is_overlay_only(self, stack_root: Path):
        """Chart defaults are left to Helm rather than copied into overlays."""
        config = _full_config()
        umbrella_values = [
            {
                "global": {
                    "shared": {
                        "tidb": {"host": "tidb.local", "port": 4000},
                    },
                },
                "tidb": {
                    "external": False,
                    "minimumVersion": "8.5.0",
                    "egress": {"enabled": False},
                },
            }
        ]

        effective = generate_effective_values(
            config,
            "tidb",
            umbrella_values,
            root_dir=stack_root,
        )

        assert "replicas" not in effective
        assert "image" not in effective
        assert effective["external"] is False
        assert effective["egress"] == {"enabled": False}

        # Global block
        assert effective["global"]["shared"]["tidb"]["host"] == "tidb.local"

    def test_tidb_without_root_dir_omits_subchart_defaults(self):
        """Without root_dir, subchart defaults are not loaded (overlay-only)."""
        config = _full_config()
        umbrella_values = [
            {
                "global": {
                    "shared": {
                        "tidb": {"host": "example"},
                    },
                },
                "tidb": {
                    "external": False,
                    "minimumVersion": "8.5.0",
                },
            }
        ]

        effective = generate_effective_values(config, "tidb", umbrella_values)

        # Only umbrella values + set overrides (no subchart defaults)
        assert effective["external"] is False
        assert effective["minimumVersion"] == "8.5.0"
        assert "replicas" not in effective  # subchart default not loaded
        assert "image" not in effective

        # Global block still included
        assert effective["global"]["shared"]["tidb"]["host"] == "example"


# ---------------------------------------------------------------------------
# Critical component rules
# ---------------------------------------------------------------------------


class TestCriticalComponentRules:
    """Verify critical component rules from the spec."""

    def test_tidb_needs_global_tidb_block(self, stack_root: Path):
        """TiDB requires parent-scoped external, minimumVersion, and
        egress.* settings from the umbrella."""
        config = _full_config()
        umbrella_values = [
            {
                "global": {
                    "shared": {
                        "tidb": {
                            "host": "tidb.example.internal",
                            "port": 4000,
                            "minimumVersion": "8.5.0",
                            "tls": {
                                "serverName": "tidb.example.internal",
                                "caSecret": {
                                    "name": "tidb-client-ca",
                                    "key": "ca.crt",
                                },
                            },
                        },
                    },
                },
                "tidb": {
                    "external": False,
                    "minimumVersion": "8.5.0",
                    "egress": {"enabled": False, "cidrs": []},
                },
            }
        ]

        effective = generate_effective_values(
            config,
            "tidb",
            umbrella_values,
            root_dir=stack_root,
        )

        # Required parent-scoped settings present
        assert effective["external"] is False
        assert effective["minimumVersion"] == "8.5.0"
        assert effective["egress"]["enabled"] is False

        # Global shared tidb block present
        assert effective["global"]["shared"]["tidb"]["host"] == "tidb.example.internal"
        assert (
            effective["global"]["shared"]["tidb"]["tls"]["caSecret"]["name"]
            == "tidb-client-ca"
        )

    def test_schema_migrator_needs_global_tidb_and_keycloak(self, stack_root: Path):
        """Schema migrator requires global.shared.tidb.* and
        global.shared.keycloak.* for state store and OIDC."""
        config = _full_config()
        umbrella_values = [
            {
                "global": {
                    "shared": {
                        "tidb": {
                            "host": "tidb.local",
                            "port": 4000,
                            "tls": {
                                "serverName": "tidb.local",
                                "caSecret": {
                                    "name": "tidb-client-ca",
                                    "key": "ca.crt",
                                },
                            },
                        },
                        "keycloak": {
                            "issuer": "https://keycloak.local/realms/middleware",
                            "jwksUri": "https://keycloak.local/realms/middleware/protocol/openid-connect/certs",
                            "schemaMigratorClientId": "bedrock-ui",
                        },
                    },
                },
                "schemaMigrator": {
                    "enabled": True,
                    "publicHostname": "migrate.example.com",
                    "traefik": {"acme": {"email": "admin@example.com"}},
                },
            }
        ]

        effective = generate_effective_values(
            config,
            "schema-migrator",
            umbrella_values,
            root_dir=stack_root,
        )

        # Schema migrator values from umbrella
        assert effective["enabled"] is True
        assert effective["publicHostname"] == "migrate.example.com"
        assert effective["traefik"]["acme"]["email"] == "admin@example.com"

        # Global shared blocks present
        assert effective["global"]["shared"]["tidb"]["host"] == "tidb.local"
        assert (
            effective["global"]["shared"]["keycloak"]["issuer"]
            == "https://keycloak.local/realms/middleware"
        )
        assert (
            effective["global"]["shared"]["keycloak"]["schemaMigratorClientId"]
            == "bedrock-ui"
        )

    def test_java_coordinator_needs_minio_and_tidb_shared(self, stack_root: Path):
        """Java coordinator needs the umbrella's TiDB and MinIO shared
        configuration. Its own chart does not supply complete TiDB shared
        defaults."""
        config = _full_config()
        umbrella_values = [
            {
                "global": {
                    "shared": {
                        "tidb": {
                            "host": "tidb.local",
                            "port": 4000,
                            "accounts": {
                                "octopus": {
                                    "database": "octopus_core",
                                    "user": "octopus_runtime",
                                    "passwordSecret": {
                                        "name": "tidb-octopus",
                                        "key": "password",
                                    },
                                },
                            },
                        },
                        "minio": {
                            "endpoint": "http://minio.local:9000",
                            "bucket": "integration-console-exports",
                            "accessKeySecret": {
                                "name": "minio-creds",
                                "key": "access-key",
                            },
                            "secretKeySecret": {
                                "name": "minio-creds",
                                "key": "secret-key",
                            },
                        },
                    },
                },
                "javaCoordinator": {
                    "enabled": True,
                },
            }
        ]

        effective = generate_effective_values(
            config,
            "java-coordinator",
            umbrella_values,
            root_dir=stack_root,
        )

        # Global shared blocks present
        assert effective["global"]["shared"]["tidb"]["host"] == "tidb.local"
        assert (
            effective["global"]["shared"]["minio"]["endpoint"]
            == "http://minio.local:9000"
        )

        # Chart defaults remain Helm's responsibility.
        assert "tidb" not in effective

    def test_tidb_schema_executor_needs_global_tidb_tls(self, stack_root: Path):
        """TiDB schema executor requires global.shared.tidb.tls.caSecret
        from the umbrella."""
        config = _full_config()
        umbrella_values = [
            {
                "global": {
                    "shared": {
                        "tidb": {
                            "tls": {
                                "caSecret": {
                                    "name": "tidb-client-ca",
                                    "key": "ca.crt",
                                },
                            },
                        },
                    },
                },
                "tidbSchemaExecutor": {
                    "enabled": True,
                },
            }
        ]

        effective = generate_effective_values(
            config,
            "tidb-schema-executor",
            umbrella_values,
            root_dir=stack_root,
        )

        # Global shared tidb tls block present
        assert (
            effective["global"]["shared"]["tidb"]["tls"]["caSecret"]["name"]
            == "tidb-client-ca"
        )

        # Component values from umbrella
        assert effective["enabled"] is True

    def test_migration_mode_preserved_in_global(self, stack_root: Path):
        """global.migration.mode must be preserved for the Java coordinator
        to control processor and consumer behavior."""
        config = _full_config()
        umbrella_values = [
            {
                "global": {
                    "migration": {"mode": "activate"},
                },
                "javaCoordinator": {},
            }
        ]

        effective = generate_effective_values(
            config,
            "java-coordinator",
            umbrella_values,
            root_dir=stack_root,
        )

        assert effective["global"]["migration"]["mode"] == "activate"

    def test_telemetry_observability_values_key(self, stack_root: Path):
        """Telemetry component extracts values under the 'telemetry' key,
        matching the Chart.yaml alias."""
        config = _full_config()
        umbrella_values = [
            {
                "global": {
                    "shared": {
                        "redpanda": {"adminPort": 9644},
                        "proxy": {"service": {"adminPort": 3002}},
                    },
                },
                "telemetry": {
                    "enabled": True,
                    "monitoring": {"enabled": True},
                },
            }
        ]

        effective = generate_effective_values(
            config,
            "telemetry",
            umbrella_values,
            root_dir=stack_root,
        )

        assert effective["enabled"] is True
        assert effective["monitoring"]["enabled"] is True
        assert effective["global"]["shared"]["redpanda"]["adminPort"] == 9644

    def test_all_components_can_render_standalone(self, stack_root: Path):
        """Exit condition: every component can be rendered standalone using
        the generated effective-values file."""
        config = _full_config()

        # Minimal umbrella values with all shared blocks
        umbrella_values = [
            {
                "global": {
                    "migration": {"mode": "activate"},
                    "shared": {
                        "tidb": {
                            "host": "tidb.local",
                            "port": 4000,
                            "minimumVersion": "8.5.0",
                            "tls": {
                                "serverName": "tidb.local",
                                "caSecret": {"name": "tidb-ca", "key": "ca.crt"},
                            },
                            "accounts": {
                                "octopus": {
                                    "database": "octopus_core",
                                    "user": "octopus",
                                    "passwordSecret": {"name": "t", "key": "p"},
                                },
                            },
                            "metricsPort": 10080,
                        },
                        "minio": {
                            "endpoint": "http://minio:9000",
                            "bucket": "bucket",
                            "accessKeySecret": {"name": "m", "key": "a"},
                            "secretKeySecret": {"name": "m", "key": "s"},
                        },
                        "redpanda": {
                            "bootstrapServers": "redpanda:9092",
                            "adminPort": 9644,
                        },
                        "keycloak": {
                            "issuer": "https://kc.local",
                            "jwksUri": "https://kc.local/certs",
                            "schemaMigratorClientId": "sm",
                        },
                        "proxy": {"service": {"adminPort": 3002}},
                        "redis": {"urlSecret": {"name": "r", "key": "u"}},
                        "javaCoordinator": {"service": {"port": 8080}},
                        "atherosSensor": {"metricsPort": 9097},
                        "atherosSearch": {
                            "metricsPort": 9090,
                            "workerMetricsPort": 9090,
                        },
                    },
                },
                "tidb": {"external": False, "minimumVersion": "8.5.0"},
                "redpanda": {"external": False},
                "minio": {"external": False},
                "redisRuntime": {"enabled": True},
                "telemetry": {"enabled": True},
                "tidbSchemaExecutor": {"enabled": True},
                "schemaMigrator": {
                    "enabled": True,
                    "publicHostname": "migrate.example.com",
                    "traefik": {"acme": {"email": "admin@example.com"}},
                },
                "javaCoordinator": {"enabled": True},
                "atherosSearch": {"enabled": True},
                "atherosSensor": {"enabled": True},
                "proxy": {"enabled": True},
            }
        ]

        # Every component should produce valid effective values without error
        for name in config.components:
            effective = generate_effective_values(
                config,
                name,
                umbrella_values,
            )
            assert isinstance(effective, dict), (
                f"{name}: effective values is not a dict"
            )
            # Global block present when include_global=True
            if config.components[name].include_global:
                assert "global" in effective, f"{name}: missing global block"
