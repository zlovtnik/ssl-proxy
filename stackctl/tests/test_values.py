"""Tests for stackctl effective values generation."""

from __future__ import annotations

import pytest

from stackctl import (
    Component,
    Defaults,
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
            {"tidb": {"setting1": "from-first", "setting2": "from-first"}},
            {"tidb": {"setting2": "from-second", "setting3": "from-second"}},
        ]

        effective = generate_effective_values(config, "tidb", umbrella_values)

        assert effective["setting1"] == "from-first"
        assert effective["setting2"] == "from-second"  # second file wins
        assert effective["setting3"] == "from-second"

    def test_runtime_overrides_applied(self):
        config = self._make_config()
        umbrella_values = [{"tidb": {"setting": "original"}}]
        runtime = {"setting": "runtime-override", "extra": "value"}

        effective = generate_effective_values(
            config, "tidb", umbrella_values, runtime_overrides=runtime
        )

        assert effective["setting"] == "runtime-override"
        assert effective["extra"] == "value"

    def test_component_set_overrides_applied(self):
        config = self._make_config()
        umbrella_values = [{"tidb": {"external": True}}]

        effective = generate_effective_values(config, "tidb", umbrella_values)

        # set: {external: false} from component config should override
        assert effective["external"] is False

    def test_empty_umbrella_values(self):
        config = self._make_config()
        umbrella_values = [{}]

        effective = generate_effective_values(config, "tidb", umbrella_values)

        # Only component set overrides
        assert effective["external"] is False

    def test_missing_values_key_returns_minimal(self):
        config = self._make_config()
        umbrella_values = [{"global": {"shared": {"tidb": {}}}}]

        effective = generate_effective_values(config, "tidb", umbrella_values)

        # values_key "tidb" doesn't exist in umbrella, but global is included
        assert "global" in effective
        assert "external" in effective  # from set override
