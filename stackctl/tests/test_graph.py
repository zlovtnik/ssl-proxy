"""Tests for stackctl graph planning."""

from __future__ import annotations

import pytest

from stackctl import (
    StackConfig,
    Component,
    build_adjacency,
    detect_cycles,
    topological_sort_waves,
    resolve_dependencies,
)


def _minimal_config() -> StackConfig:
    """Create a minimal valid config for testing."""
    return StackConfig(
        version=1,
        components={
            "infra": Component(type="helm", release="infra", chart="./charts/infra"),
            "db": Component(
                type="helm",
                release="db",
                chart="./charts/db",
                depends_on=["infra"],
            ),
            "app": Component(
                type="helm",
                release="app",
                chart="./charts/app",
                depends_on=["db"],
            ),
        },
    )


def _full_stack_config() -> StackConfig:
    """Create the full 11-component stack configuration."""
    return StackConfig(
        version=1,
        components={
            "tidb": Component(
                type="helm",
                release="ssl-proxy-tidb",
                chart="./helm/ssl-proxy/charts/tidb",
            ),
            "redpanda": Component(
                type="helm",
                release="ssl-proxy-redpanda",
                chart="./helm/ssl-proxy/charts/redpanda",
            ),
            "minio": Component(
                type="helm",
                release="ssl-proxy-minio",
                chart="./helm/ssl-proxy/charts/minio",
            ),
            "redis": Component(
                type="helm",
                release="ssl-proxy-redis",
                chart="./helm/ssl-proxy/charts/redis-runtime",
            ),
            "telemetry": Component(
                type="helm",
                release="ssl-proxy-telemetry",
                chart="./helm/ssl-proxy/charts/telemetry",
            ),
            "tidb-schema-executor": Component(
                type="helm-job",
                release="ssl-proxy-tidb-schema",
                chart="./helm/ssl-proxy/charts/tidb-schema-executor",
                depends_on=["tidb"],
            ),
            "schema-migrator": Component(
                type="helm",
                release="ssl-proxy-schema-migrator",
                chart="./helm/ssl-proxy/charts/schema-migrator",
                depends_on=["tidb", "tidb-schema-executor"],
            ),
            "java-coordinator": Component(
                type="helm",
                release="ssl-proxy-coordinator",
                chart="./helm/ssl-proxy/charts/java-coordinator",
                depends_on=["tidb", "redpanda", "minio", "schema-migrator"],
            ),
            "atheros-search": Component(
                type="helm",
                release="ssl-proxy-atheros-search",
                chart="./helm/ssl-proxy/charts/atheros-search",
                depends_on=["tidb", "redpanda", "schema-migrator"],
            ),
            "atheros-sensor": Component(
                type="helm",
                release="ssl-proxy-atheros-sensor",
                chart="./helm/ssl-proxy/charts/atheros-sensor",
                depends_on=["redpanda"],
            ),
            "proxy": Component(
                type="helm",
                release="ssl-proxy-proxy",
                chart="./helm/ssl-proxy/charts/proxy",
                depends_on=["redpanda", "java-coordinator", "atheros-search"],
            ),
        },
    )


class TestBuildAdjacency:
    """Test adjacency list construction."""

    def test_simple_chain(self):
        config = _minimal_config()
        adj = build_adjacency(config)
        assert adj["infra"] == ["db"]
        assert adj["db"] == ["app"]
        assert adj["app"] == []

    def test_full_stack_adjacency(self):
        config = _full_stack_config()
        adj = build_adjacency(config)
        # tidb has no dependents listed in adjacency (others depend on it)
        assert "tidb-schema-executor" in adj["tidb"]
        assert "java-coordinator" in adj["redpanda"]
        assert "atheros-sensor" in adj["redpanda"]
        assert "proxy" in adj["java-coordinator"]


class TestDetectCycles:
    """Test cycle detection."""

    def test_no_cycle(self):
        config = _minimal_config()
        adj = build_adjacency(config)
        cycles = detect_cycles(adj)
        assert cycles == []

    def test_simple_cycle(self):
        graph = {"a": ["b"], "b": ["c"], "c": ["a"]}
        cycles = detect_cycles(graph)
        assert len(cycles) >= 1
        # The cycle should contain a, b, c
        cycle_nodes = set(cycles[0])
        assert cycle_nodes == {"a", "b", "c"}

    def test_self_loop(self):
        graph = {"a": ["a"]}
        cycles = detect_cycles(graph)
        assert len(cycles) >= 1

    def test_independent_nodes_no_cycle(self):
        graph = {"a": [], "b": [], "c": []}
        cycles = detect_cycles(graph)
        assert cycles == []


class TestTopologicalSortWaves:
    """Test topological sort into waves."""

    def test_simple_chain_three_waves(self):
        config = _minimal_config()
        waves = topological_sort_waves(config)
        assert len(waves) == 3
        assert waves[0] == ["infra"]
        assert waves[1] == ["db"]
        assert waves[2] == ["app"]

    def test_parallel_components_share_wave(self):
        config = StackConfig(
            version=1,
            components={
                "a": Component(type="helm", release="a", chart="./charts/a"),
                "b": Component(type="helm", release="b", chart="./charts/b"),
                "c": Component(
                    type="helm",
                    release="c",
                    chart="./charts/c",
                    depends_on=["a", "b"],
                ),
            },
        )
        waves = topological_sort_waves(config)
        assert len(waves) == 2
        assert set(waves[0]) == {"a", "b"}
        assert waves[1] == ["c"]

    def test_full_stack_five_waves(self):
        config = _full_stack_config()
        waves = topological_sort_waves(config)
        assert len(waves) == 5

        # Wave 1: infrastructure (no deps)
        wave1 = set(waves[0])
        assert "tidb" in wave1
        assert "redpanda" in wave1
        assert "minio" in wave1
        assert "redis" in wave1
        assert "telemetry" in wave1

        # Wave 2: tidb-schema-executor (depends on tidb), atheros-sensor (depends on redpanda)
        wave2 = set(waves[1])
        assert "tidb-schema-executor" in wave2
        assert "atheros-sensor" in wave2

        # Wave 3: schema-migrator (depends on tidb, tidb-schema-executor)
        assert "schema-migrator" in waves[2]

        # Wave 4: applications
        wave4 = set(waves[3])
        assert "java-coordinator" in wave4
        assert "atheros-search" in wave4

        # Wave 5: proxy (depends on java-coordinator, atheros-search)
        assert "proxy" in waves[4]


class TestResolveDependencies:
    """Test dependency resolution with targeting."""

    def test_target_component_includes_dependencies(self):
        config = _full_stack_config()
        waves = resolve_dependencies(config, target_component="atheros-search")
        # atheros-search depends on tidb, redpanda, schema-migrator
        # schema-migrator depends on tidb, tidb-schema-executor
        # tidb-schema-executor depends on tidb
        all_components = set()
        for wave in waves:
            all_components.update(wave)

        assert "atheros-search" in all_components
        assert "tidb" in all_components
        assert "redpanda" in all_components
        assert "schema-migrator" in all_components
        assert "tidb-schema-executor" in all_components

        # Should NOT include components not in the dependency chain
        assert "proxy" not in all_components
        assert "java-coordinator" not in all_components
        assert "atheros-sensor" not in all_components

    def test_target_unknown_component_raises(self):
        config = _minimal_config()
        with pytest.raises(ValueError) as exc_info:
            resolve_dependencies(config, target_component="nonexistent")
        assert "nonexistent" in str(exc_info.value)

    def test_from_wave_filters_correctly(self):
        config = _full_stack_config()
        waves = resolve_dependencies(config, from_wave=4)
        assert len(waves) == 2
        all_components = set()
        for wave in waves:
            all_components.update(wave)
        assert "java-coordinator" in all_components
        assert "proxy" in all_components

    def test_from_wave_invalid_raises(self):
        config = _minimal_config()
        with pytest.raises(ValueError) as exc_info:
            resolve_dependencies(config, from_wave=10)
        assert "Invalid from_wave" in str(exc_info.value)

    def test_no_filter_returns_all_waves(self):
        config = _minimal_config()
        waves = resolve_dependencies(config)
        assert len(waves) == 3
