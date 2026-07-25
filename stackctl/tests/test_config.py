"""Tests for stackctl configuration parsing."""

from __future__ import annotations

import tempfile
from pathlib import Path
from textwrap import dedent

import pytest
import yaml

from stackctl import (
    Component,
    Gate,
    JobConfig,
    StackConfig,
    validate_config,
    load_config,
)


class TestComponentTypes:
    """Test supported component types."""

    def test_valid_helm_type(self):
        comp = Component(type="helm", release="test-release", chart="./charts/test")
        assert comp.type == "helm"

    def test_valid_helm_job_type(self):
        comp = Component(
            type="helm-job",
            release="test-release",
            chart="./charts/test",
            job=JobConfig(),
        )
        assert comp.type == "helm-job"

    def test_valid_manifest_type(self):
        comp = Component(type="manifest", release="test-release")
        assert comp.type == "manifest"

    def test_valid_external_check_type(self):
        comp = Component(type="external-check", release="test-release")
        assert comp.type == "external-check"

    def test_invalid_component_type(self):
        with pytest.raises(Exception) as exc_info:
            Component(type="invalid", release="test-release")
        assert "Invalid component type" in str(exc_info.value)

    def test_invalid_type_not_in_set(self):
        with pytest.raises(Exception):
            Component(type="statefulset", release="test-release")


class TestGate:
    """Test Gate model."""

    def test_resource_gate(self):
        gate = Gate(resource="statefulset/ssl-proxy-tidb")
        assert gate.resource == "statefulset/ssl-proxy-tidb"
        assert gate.discover is None

    def test_discover_gate(self):
        gate = Gate(discover={"kind": "Deployment"})
        assert gate.discover == {"kind": "Deployment"}
        assert gate.resource is None

    def test_discover_requires_kind(self):
        with pytest.raises(Exception) as exc_info:
            Gate(discover={"label": "app=test"})
        assert "kind" in str(exc_info.value)

    def test_gate_with_condition(self):
        gate = Gate(discover={"kind": "Job"}, condition="complete")
        assert gate.condition == "complete"


class TestStackConfig:
    """Test root configuration model."""

    def test_valid_config(self):
        config = StackConfig(
            version=1,
            components={
                "test": Component(type="helm", release="test", chart="./charts/test")
            },
        )
        assert config.version == 1
        assert "test" in config.components

    def test_invalid_version(self):
        with pytest.raises(Exception) as exc_info:
            StackConfig(version=2, components={})
        assert "Unsupported version" in str(exc_info.value)

    def test_defaults_applied(self):
        config = StackConfig(version=1)
        assert config.defaults.namespace == "default"
        assert config.defaults.timeout == "10m"
        assert config.defaults.values == []

    def test_helm_requires_chart(self):
        comp = Component(type="helm", release="test")
        # chart is optional at model level, validated in validate_config
        assert comp.chart is None

    def test_helm_job_requires_job_config(self):
        comp = Component(
            type="helm-job", release="test", chart="./charts/test", job=JobConfig()
        )
        assert comp.job is not None

    def test_depends_on_list(self):
        comp = Component(
            type="helm",
            release="test",
            chart="./charts/test",
            depends_on=["dep-a", "dep-b"],
        )
        assert comp.depends_on == ["dep-a", "dep-b"]


class TestValidateConfig:
    """Test configuration validation."""

    def test_valid_config_passes(self):
        config = StackConfig(
            version=1,
            components={
                "a": Component(type="helm", release="a", chart="./charts/a"),
                "b": Component(
                    type="helm",
                    release="b",
                    chart="./charts/b",
                    depends_on=["a"],
                ),
            },
        )
        errors = validate_config(config)
        assert errors == []

    def test_unknown_dependency_detected(self):
        config = StackConfig(
            version=1,
            components={
                "a": Component(
                    type="helm",
                    release="a",
                    chart="./charts/a",
                    depends_on=["nonexistent"],
                ),
            },
        )
        errors = validate_config(config)
        assert len(errors) == 1
        assert "nonexistent" in errors[0]
        assert "unknown" in errors[0].lower()

    def test_helm_missing_chart_detected(self):
        config = StackConfig(
            version=1,
            components={
                "a": Component(type="helm", release="a"),
            },
        )
        errors = validate_config(config)
        assert len(errors) == 1
        assert "chart" in errors[0]

    def test_helm_job_missing_job_config_detected(self):
        config = StackConfig(
            version=1,
            components={
                "a": Component(type="helm-job", release="a", chart="./charts/a"),
            },
        )
        errors = validate_config(config)
        assert len(errors) == 1
        assert "job" in errors[0]

    def test_multiple_errors(self):
        config = StackConfig(
            version=1,
            components={
                "a": Component(
                    type="helm",
                    release="a",
                    chart="./charts/a",
                    depends_on=["missing1", "missing2"],
                ),
            },
        )
        errors = validate_config(config)
        assert len(errors) == 2


class TestLoadConfig:
    """Test loading configuration from YAML files."""

    def test_load_valid_file(self):
        config_data = {
            "version": 1,
            "defaults": {"namespace": "test-ns", "timeout": "5m"},
            "components": {
                "web": {
                    "type": "helm",
                    "release": "web-release",
                    "chart": "./charts/web",
                }
            },
        }
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            yaml.dump(config_data, f)
            f.flush()

            config = load_config(f.name)
            assert config.version == 1
            assert config.defaults.namespace == "test-ns"
            assert "web" in config.components

    def test_load_missing_file(self):
        with pytest.raises(FileNotFoundError):
            load_config("/nonexistent/path.yaml")

    def test_load_empty_file(self):
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yaml", delete=False
        ) as f:
            f.write("")
            f.flush()

            with pytest.raises(ValueError) as exc_info:
                load_config(f.name)
            assert "Empty" in str(exc_info.value)
