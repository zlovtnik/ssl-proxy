#!/usr/bin/env python3
"""Canonical stack deployment orchestrator.

Phase 1: Configuration parsing and dependency graph planning.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    field_validator,
    model_validator,
)

# ---------------------------------------------------------------------------
# Supported component types
# ---------------------------------------------------------------------------

COMPONENT_TYPES = frozenset({"helm", "helm-job", "manifest", "external-check"})
STAGES = (
    "bootstrap",
    "infrastructure",
    "schema-executor",
    "schema-migrator",
    "applications",
    "proxy",
)
NUMBERED_STAGES = STAGES[1:]
TIMEOUT_RE = re.compile(r"^(?:\d+h)?(?:\d+m)?(?:\d+s)?$")


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class StrictModel(BaseModel):
    """Forbid misspelled or unsupported configuration fields."""

    model_config = ConfigDict(extra="forbid")


class Gate(StrictModel):
    """A readiness gate for a component."""

    resource: str | None = None
    discover: dict[str, str] | None = None
    condition: Literal["available", "ready", "complete", "established"] | None = None

    @model_validator(mode="after")
    def validate_target(self) -> Gate:
        if (self.resource is None) == (self.discover is None):
            raise ValueError("gate must set exactly one of resource or discover")
        if self.discover is not None:
            unknown = set(self.discover) - {"kind", "selector"}
            if unknown:
                raise ValueError(f"unknown discover fields: {', '.join(sorted(unknown))}")
            if not self.discover.get("kind") or not self.discover.get("selector"):
                raise ValueError("discover must contain non-empty kind and selector")
        return self


class JobConfig(StrictModel):
    """Job-specific configuration for helm-job components."""

    rerun: Literal["replace"] = "replace"
    name: str | None = None


class Check(StrictModel):
    """Post-readiness application check."""

    type: Literal["http", "tcp", "exec", "resource"]
    target: str
    port: int | None = Field(default=None, ge=1, le=65535)
    path: str | None = None
    command: list[str] = Field(default_factory=list)
    timeout: str = "60s"

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, value: str) -> str:
        return _validate_timeout(value)

    @model_validator(mode="after")
    def validate_shape(self) -> Check:
        if self.type in ("http", "tcp") and self.port is None:
            raise ValueError(f"{self.type} check requires port")
        if self.type == "exec" and not self.command:
            raise ValueError("exec check requires a non-empty command")
        if self.type != "exec" and self.command:
            raise ValueError("command is supported only by exec checks")
        if self.type != "http" and self.path is not None:
            raise ValueError("path is supported only by http checks")
        return self


class ComponentBase(StrictModel):
    """Fields common to every component kind."""

    type: str
    depends_on: list[str] = Field(default_factory=list)
    stage: (
        Literal[
            "bootstrap",
            "infrastructure",
            "schema-executor",
            "schema-migrator",
            "applications",
            "proxy",
        ]
        | None
    ) = None
    gates: list[Gate] = Field(default_factory=list)
    checks: list[Check] = Field(default_factory=list)
    timeout: str | None = None

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, value: str | None) -> str | None:
        return _validate_timeout(value) if value is not None else None


class HelmComponent(ComponentBase):
    type: Literal["helm"] = "helm"
    release: str
    chart: str
    values_key: str | None = None
    include_global: bool = True
    set: dict[str, Any] = Field(default_factory=dict)
    rollback: Literal["none", "auto"] = "none"
    rollback_on_failure: bool = False

    @model_validator(mode="after")
    def normalize_rollback(self) -> HelmComponent:
        if self.values_key is None:
            self.values_key = self.release
        if self.rollback_on_failure:
            self.rollback = "auto"
        return self


class HelmJobComponent(ComponentBase):
    type: Literal["helm-job"]
    release: str
    chart: str
    values_key: str | None = None
    include_global: bool = True
    set: dict[str, Any] = Field(default_factory=dict)
    job: JobConfig
    rollback: Literal["none"] = "none"
    rollback_on_failure: Literal[False] = False

    @model_validator(mode="after")
    def infer_values_key(self) -> HelmJobComponent:
        if self.values_key is None:
            self.values_key = self.release
        return self


class ManifestComponent(ComponentBase):
    type: Literal["manifest"]
    paths: list[str] = Field(min_length=1)
    field_manager: str = "stackctl"


class ExternalCheckComponent(ComponentBase):
    type: Literal["external-check"]
    checks: list[Check] = Field(min_length=1)


ComponentModel = Annotated[
    HelmComponent | HelmJobComponent | ManifestComponent | ExternalCheckComponent,
    Field(discriminator="type"),
]
_COMPONENT_ADAPTER = TypeAdapter(ComponentModel)


def Component(**data: Any) -> ComponentModel:
    """Compatibility constructor backed by the strict discriminated union."""

    try:
        return _COMPONENT_ADAPTER.validate_python(data)
    except Exception as exc:
        if "union_tag_invalid" in str(exc):
            valid = ", ".join(sorted(COMPONENT_TYPES))
            raise ValueError(
                f"Invalid component type {data.get('type')!r}. Must be one of: {valid}"
            ) from exc
        raise


def _validate_timeout(value: str) -> str:
    if not value or not TIMEOUT_RE.fullmatch(value):
        raise ValueError("timeout must use Helm duration syntax such as 30s, 10m, or 1h30m")
    parts = re.findall(r"(\d+)([hms])", value)
    if not parts or all(int(amount) == 0 for amount, _ in parts):
        raise ValueError("timeout must be greater than zero")
    return value


class Defaults(StrictModel):
    """Default settings applied to all components."""

    namespace: str = "default"
    timeout: str = "10m"
    values: list[str] = Field(default_factory=list)
    global_overrides: dict[str, Any] = Field(default_factory=dict)
    artifact_dir: str = "stackctl-artifacts"
    max_parallel: int = Field(default=4, ge=1, le=32)

    @field_validator("timeout")
    @classmethod
    def validate_timeout(cls, value: str) -> str:
        return _validate_timeout(value)


class StackConfig(StrictModel):
    """Root configuration model."""

    version: int
    defaults: Defaults = Field(default_factory=Defaults)
    components: dict[str, ComponentModel] = Field(default_factory=dict)

    @field_validator("version")
    @classmethod
    def validate_version(cls, v: int) -> int:
        if v != 1:
            raise ValueError(f"Unsupported version {v}. Only version 1 is supported.")
        return v


# ---------------------------------------------------------------------------
# Configuration loading
# ---------------------------------------------------------------------------


def load_config(file_path: str | Path) -> StackConfig:
    """Load and parse a stack.yaml configuration file."""
    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"Configuration file not found: {path}")

    with open(path) as f:
        raw = yaml.safe_load(f)

    if raw is None:
        raise ValueError(f"Empty configuration file: {path}")

    return StackConfig.model_validate(raw)


def validate_config(config: StackConfig) -> list[str]:
    """Validate configuration consistency. Returns list of error messages."""
    errors: list[str] = []

    known_components = set(config.components.keys())
    explicit_stages = {
        component.stage for component in config.components.values() if component.stage
    }
    if explicit_stages and any(component.stage is None for component in config.components.values()):
        errors.append("Every component must declare a stage when explicit stages are used")

    for name, component in config.components.items():
        # Check that all dependencies exist
        for dep in component.depends_on:
            if dep not in known_components:
                errors.append(f"Component '{name}' depends on unknown component '{dep}'")
                continue

            if component.stage and config.components[dep].stage:
                source = STAGES.index(config.components[dep].stage)
                target = STAGES.index(component.stage)
                if source >= target:
                    errors.append(
                        f"Component '{name}' dependency '{dep}' must be in an earlier stage"
                    )

        if component.type in ("helm", "helm-job") and not component.chart:
            errors.append(f"Component '{name}' of type '{component.type}' requires a chart")
        if component.type == "helm-job" and not component.job:
            errors.append(f"Component '{name}' of type 'helm-job' requires job configuration")
        if component.type == "manifest" and not component.paths:
            errors.append(f"Manifest component '{name}' requires one or more paths")
        if component.type == "external-check" and not component.checks:
            errors.append(f"External-check component '{name}' requires checks")

        if component.stage == "bootstrap" and component.depends_on:
            errors.append(f"Bootstrap component '{name}' cannot have dependencies")

    return errors


# ---------------------------------------------------------------------------
# Graph operations
# ---------------------------------------------------------------------------


def build_adjacency(config: StackConfig) -> dict[str, list[str]]:
    """Build adjacency list from component dependencies."""
    graph: dict[str, list[str]] = {}
    for name in config.components:
        graph[name] = []
    for name, component in config.components.items():
        for dep in component.depends_on:
            if dep in graph:
                graph[dep].append(name)
    return graph


def detect_cycles(graph: dict[str, list[str]]) -> list[list[str]]:
    """Detect cycles in the dependency graph. Returns list of cycles found."""
    WHITE, GRAY, BLACK = 0, 1, 2
    color: dict[str, int] = {node: WHITE for node in graph}
    parent: dict[str, str | None] = {node: None for node in graph}
    cycles: list[list[str]] = []

    def dfs(node: str) -> None:
        color[node] = GRAY
        for neighbor in graph.get(node, []):
            if neighbor not in color:
                continue
            if color[neighbor] == GRAY:
                # Found a cycle — reconstruct it
                cycle = [neighbor]
                current = node
                while current != neighbor:
                    cycle.append(current)
                    current = parent[current]  # type: ignore[assignment]
                    if current is None:
                        break
                cycle.reverse()
                cycles.append(cycle)
            elif color[neighbor] == WHITE:
                parent[neighbor] = node
                dfs(neighbor)
        color[node] = BLACK

    for node in graph:
        if color[node] == WHITE:
            dfs(node)

    return cycles


def topological_sort_waves(config: StackConfig) -> list[list[str]]:
    """Compute deployment waves via topological sort.

    Returns a list of waves, where each wave is a list of component names
    that can be deployed in parallel.
    """
    in_degree: dict[str, int] = {name: 0 for name in config.components}
    for name, component in config.components.items():
        for dep in component.depends_on:
            if dep in in_degree:
                in_degree[name] += 1

    waves: list[list[str]] = []
    remaining = set(config.components.keys())

    while remaining:
        # Find all nodes with zero in-degree
        ready = sorted([n for n in remaining if in_degree[n] == 0])
        if not ready:
            # All remaining nodes have unsatisfied deps — shouldn't happen
            # if cycles were detected earlier
            raise ValueError(f"Circular dependency detected among: {sorted(remaining)}")
        waves.append(ready)
        for node in ready:
            remaining.remove(node)
            # Decrease in-degree for all nodes that depend on this one
            adjacency = build_adjacency(config)
            for dependent in adjacency.get(node, []):
                if dependent in remaining:
                    in_degree[dependent] -= 1

    return waves


def staged_waves(config: StackConfig) -> tuple[list[str], list[list[str]]]:
    """Return bootstrap separately from the five fixed deployment stages."""

    if not any(component.stage for component in config.components.values()):
        return [], topological_sort_waves(config)
    errors = validate_config(config)
    if errors:
        raise ValueError("; ".join(errors))
    by_stage: dict[str, list[str]] = {stage: [] for stage in STAGES}
    for name, component in config.components.items():
        assert component.stage is not None
        by_stage[component.stage].append(name)
    return sorted(by_stage["bootstrap"]), [sorted(by_stage[stage]) for stage in NUMBERED_STAGES]


def resolve_dependencies(
    config: StackConfig,
    target_component: str | None = None,
    from_wave: int | None = None,
    include_descendants: bool = False,
) -> list[list[str]]:
    """Resolve the deployment plan, optionally targeting a specific component.

    When target_component is specified, includes the target and all
    transitive dependencies.
    """
    bootstrap, numbered = staged_waves(config)
    all_waves = ([bootstrap] if bootstrap else []) + numbered

    if target_component is not None:
        if target_component not in config.components:
            raise ValueError(f"Unknown component: {target_component}")

        # Collect all transitive dependencies
        required: set[str] = set()
        stack = [target_component]
        while stack:
            current = stack.pop()
            if current in required:
                continue
            required.add(current)
            for dep in config.components[current].depends_on:
                stack.append(dep)

        if include_descendants:
            adjacency = build_adjacency(config)
            stack = [target_component]
            while stack:
                current = stack.pop()
                for child in adjacency[current]:
                    if child not in required:
                        required.add(child)
                        stack.append(child)

        # Filter waves to only include required components
        filtered_waves = []
        for wave in all_waves:
            filtered = [c for c in wave if c in required]
            if filtered:
                filtered_waves.append(filtered)
        return filtered_waves

    if from_wave is not None:
        numbered_waves = numbered if bootstrap else all_waves
        if from_wave < 1 or from_wave > len(numbered_waves):
            raise ValueError(f"Invalid from_wave {from_wave}. Valid range: 1-{len(numbered_waves)}")
        return numbered_waves[from_wave - 1 :]

    return all_waves


# ---------------------------------------------------------------------------
# Effective values generation
# ---------------------------------------------------------------------------


def deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dictionaries. Override values take precedence."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def _load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file and return its contents as a dict."""
    with open(path) as f:
        data = yaml.safe_load(f)
    return data if isinstance(data, dict) else {}


def generate_effective_values(
    config: StackConfig,
    component_name: str,
    umbrella_values: list[dict[str, Any]],
    runtime_overrides: dict[str, Any] | None = None,
    root_dir: str | Path | None = None,
) -> dict[str, Any]:
    """Generate effective values for a component.

    Only the component overlay and global contract are generated. Helm remains
    responsible for loading the standalone chart's defaults.
    """
    component = config.components[component_name]
    if component.type not in ("helm", "helm-job"):
        raise ValueError(f"Component {component_name!r} does not have Helm values")

    if root_dir:
        chart_path = Path(root_dir) / component.chart
        values_file = chart_path / "values.yaml"
        if not chart_path.is_dir():
            raise FileNotFoundError(f"Chart directory not found: {chart_path}")
        if not values_file.is_file():
            raise FileNotFoundError(f"Chart values file not found: {values_file}")

    merged: dict[str, Any] = {}
    for values_file in umbrella_values:
        merged = deep_merge(merged, values_file)
    if runtime_overrides:
        unknown = set(runtime_overrides) - set(merged)
        if unknown:
            raise ValueError(f"Unknown top-level override keys: {', '.join(sorted(unknown))}")
        merged = deep_merge(merged, runtime_overrides)

    if component.values_key not in merged:
        raise ValueError(
            f"Component {component_name!r} values_key {component.values_key!r} "
            "does not exist in merged umbrella values"
        )
    component_values = merged[component.values_key]
    if not isinstance(component_values, dict):
        raise ValueError(f"Component {component_name!r} values_key must map to an object")
    effective = component_values.copy()

    if component.include_global:
        global_values = merged.get("global")
        if not isinstance(global_values, dict):
            raise ValueError("Merged umbrella values must contain a global object")
        effective["global"] = deep_merge(global_values, config.defaults.global_overrides)

    if component.set:
        effective = deep_merge(effective, component.set)

    return effective


def parse_overrides(
    yaml_values: list[str],
    string_values: list[str],
    literal_values: list[str],
) -> dict[str, Any]:
    """Parse dotted umbrella overrides with Helm-compatible scalar semantics."""

    result: dict[str, Any] = {}
    for entries, preserve_string in (
        (yaml_values, False),
        (string_values, True),
        (literal_values, True),
    ):
        for entry in entries:
            if "=" not in entry:
                raise ValueError(f"Override must be KEY=VALUE: {entry!r}")
            key, raw = entry.split("=", 1)
            parts = key.split(".")
            if not key or any(not part for part in parts):
                raise ValueError(f"Invalid override key: {key!r}")
            value = raw if preserve_string else yaml.safe_load(raw)
            cursor = result
            for part in parts[:-1]:
                existing = cursor.setdefault(part, {})
                if not isinstance(existing, dict):
                    raise ValueError(f"Override path conflicts at {part!r}")
                cursor = existing
            cursor[parts[-1]] = value
    return result


def load_umbrella_values(config: StackConfig, root_dir: Path) -> list[dict[str, Any]]:
    """Load every configured values file; missing or non-object files are errors."""

    loaded: list[dict[str, Any]] = []
    for configured in config.defaults.values:
        path = Path(configured)
        if not path.is_absolute():
            path = root_dir / path
        if not path.is_file():
            raise FileNotFoundError(f"Values file not found: {path}")
        data = _load_yaml(path)
        if not data:
            raise ValueError(f"Values file is empty or not an object: {path}")
        loaded.append(data)
    return loaded


# ---------------------------------------------------------------------------
# CLI commands
# ---------------------------------------------------------------------------


def cmd_plan(args: argparse.Namespace) -> int:
    """Print the deployment plan (dependency graph and waves)."""
    config = load_config(args.file)
    errors = validate_config(config)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    cycles = detect_cycles(build_adjacency(config))
    if cycles:
        for cycle in cycles:
            print(
                f"ERROR: Dependency cycle detected: {' -> '.join(cycle)} -> {cycle[0]}",
                file=sys.stderr,
            )
        return 1

    waves = resolve_dependencies(
        config,
        target_component=args.component,
        from_wave=args.from_wave,
        include_descendants=args.include_descendants,
    )
    bootstrap_names = {
        name for name, component in config.components.items() if component.stage == "bootstrap"
    }
    bootstrap = next((wave for wave in waves if wave and set(wave) <= bootstrap_names), [])
    numbered = [wave for wave in waves if wave is not bootstrap]
    wave_items = []
    for wave in numbered:
        stage = (
            config.components[wave[0]].stage if wave and config.components[wave[0]].stage else None
        )
        number = (
            NUMBERED_STAGES.index(stage) + 1 if stage in NUMBERED_STAGES else len(wave_items) + 1
        )
        wave_items.append(
            {
                "number": number,
                "stage": stage or f"wave-{number}",
                "components": wave,
            }
        )
    payload = {
        "components": len(config.components),
        "bootstrap": bootstrap,
        "waves": wave_items,
    }
    if args.output == "json":
        print(json.dumps(payload, indent=2, sort_keys=True))
        return 0

    print(f"Stack Plan ({len(config.components)} components)")
    if bootstrap:
        print("\nBootstrap")
        for comp_name in bootstrap:
            print(f"  {comp_name} [{config.components[comp_name].type}]")
    for item in payload["waves"]:
        print(f"\nWave {item['number']} ({item['stage']})")
        for comp_name in item["components"]:
            comp = config.components[comp_name]
            deps = f" (depends: {', '.join(comp.depends_on)})" if comp.depends_on else ""
            print(f"  {comp_name} [{comp.type}]{deps}")

    if args.verbose:
        print("Configuration Details:")
        print(f"  Namespace: {config.defaults.namespace}")
        print(f"  Timeout: {config.defaults.timeout}")
        print(f"  Values files: {len(config.defaults.values)}")
        for vf in config.defaults.values:
            print(f"    - {vf}")

    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate configuration and every rendered Kubernetes document."""
    from .rendering import render_component, validate_rendered

    config = load_config(args.file)
    errors = validate_config(config)

    if errors:
        print("Validation FAILED:\n")
        for error in errors:
            print(f"  - {error}")
        return 1

    cycles = detect_cycles(build_adjacency(config))
    if cycles:
        print("Validation FAILED - dependency cycles detected:\n")
        for cycle in cycles:
            print(f"  - {' -> '.join(cycle)} -> {cycle[0]}")
        return 1

    root_dir = _repo_root(Path(args.file))
    values = load_umbrella_values(config, root_dir)
    overrides = _args_overrides(args)
    rendered = [
        render_component(
            name,
            config,
            root_dir,
            values,
            overrides,
            args.namespace or config.defaults.namespace,
        )
        for name, component in config.components.items()
        if component.type in ("helm", "helm-job")
    ]
    errors.extend(validate_rendered(rendered, config))
    if errors:
        _print_errors(errors, args.output)
        return 1

    if args.output == "json":
        print(
            json.dumps(
                {
                    "valid": True,
                    "components": len(config.components),
                    "resources": sum(len(item.resources) for item in rendered),
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print(
            f"Validation PASSED ({len(config.components)} components, "
            f"{sum(len(item.resources) for item in rendered)} resources)"
        )

    if args.verbose:
        _, waves = staged_waves(config)
        for i, wave in enumerate(waves, 1):
            print(f"  Wave {i}: {', '.join(wave)}")

    return 0


def cmd_render(args: argparse.Namespace) -> int:
    """Render standalone releases using effective umbrella overlays."""
    from .deploy import _redact_dict
    from .rendering import (
        render_component,
        safe_artifact_dir,
        validate_rendered,
        write_render_artifacts,
    )

    config = load_config(args.file)
    root_dir = _repo_root(Path(args.file))
    values = load_umbrella_values(config, root_dir)
    overrides = _args_overrides(args)
    names = _selected_components(config, args)
    rendered = [
        render_component(
            name,
            config,
            root_dir,
            values,
            overrides,
            args.namespace or config.defaults.namespace,
        )
        for name in names
        if config.components[name].type in ("helm", "helm-job")
    ]
    errors = validate_rendered(rendered, config)
    if errors:
        _print_errors(errors, args.output)
        return 1
    artifact = safe_artifact_dir(
        root_dir, args.artifact_dir or f"{config.defaults.artifact_dir}/render"
    )
    write_render_artifacts(artifact, rendered, _redact_dict)
    if args.output == "json":
        print(
            json.dumps(
                {
                    "artifact_dir": str(artifact),
                    "components": [
                        {"name": item.name, "resources": len(item.resources)} for item in rendered
                    ],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        print("\n---\n".join(item.manifest.rstrip() for item in rendered))
    return 0


def cmd_compare(args: argparse.Namespace) -> int:
    """Compare normalized umbrella and split-release manifests."""
    from .deploy import _redact_dict
    from .rendering import (
        parity_diff,
        render_component,
        render_umbrella,
        safe_artifact_dir,
        write_parity_artifacts,
    )

    config = load_config(args.file)
    root_dir = _repo_root(Path(args.file))
    values = load_umbrella_values(config, root_dir)
    overrides = _args_overrides(args)
    namespace = args.namespace or config.defaults.namespace
    split = [
        render_component(name, config, root_dir, values, overrides, namespace)
        for name, component in config.components.items()
        if component.type in ("helm", "helm-job")
    ]
    umbrella = render_umbrella(root_dir / "helm" / "ssl-proxy", values, overrides, namespace)
    differences = parity_diff(umbrella, [resource for item in split for resource in item.resources])
    artifact = safe_artifact_dir(
        root_dir,
        args.artifact_dir or f"{config.defaults.artifact_dir}/compare",
    )
    write_parity_artifacts(
        artifact,
        config,
        root_dir,
        umbrella,
        split,
        differences,
        _redact_dict,
    )
    if args.output == "json":
        print(
            json.dumps(
                {
                    "parity": not differences,
                    "differences": differences,
                    "artifact_dir": str(artifact),
                },
                indent=2,
            )
        )
    elif differences:
        _print_errors(differences, "text")
    else:
        print("Manifest parity PASSED")
    return 1 if differences else 0


def cmd_dry_run(args: argparse.Namespace) -> int:
    """Run Helm server-side dry-runs without retaining raw values."""
    return _run_deploy(args, dry_run=True)


def cmd_deploy(args: argparse.Namespace) -> int:
    """Deploy components wave-by-wave with concurrent execution."""
    return _run_deploy(args, dry_run=False)


def _run_deploy(args: argparse.Namespace, dry_run: bool) -> int:
    import asyncio

    from .deploy import DeployOptions, deploy_stack

    config = load_config(args.file)
    errors = validate_config(config)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        return 1

    cycles = detect_cycles(build_adjacency(config))
    if cycles:
        for cycle in cycles:
            print(
                f"ERROR: Dependency cycle detected: {' -> '.join(cycle)} -> {cycle[0]}",
                file=sys.stderr,
            )
        return 1

    root_dir = _repo_root(Path(args.file))
    umbrella_values = load_umbrella_values(config, root_dir)
    namespace = args.namespace or config.defaults.namespace
    configured_artifact = (
        args.artifact_dir or getattr(args, "work_dir", None) or config.defaults.artifact_dir
    )
    from .rendering import safe_artifact_dir

    artifact_base = safe_artifact_dir(root_dir, configured_artifact)

    options = DeployOptions(
        namespace=namespace,
        context=args.kube_context,
        kubeconfig=args.kubeconfig,
        root_dir=str(root_dir),
        umbrella_values=umbrella_values,
        target_component=args.component,
        from_wave=args.from_wave,
        dry_run=dry_run,
        verbose=args.verbose,
        keep_artifacts=getattr(args, "keep_artifacts", True),
        work_dir=None,
        artifact_dir=str(artifact_base),
        max_parallel=args.max_parallel or config.defaults.max_parallel,
        include_descendants=args.include_descendants,
        runtime_overrides=_args_overrides(args),
    )

    result = asyncio.run(deploy_stack(config, options))

    if args.output == "json":
        print(
            json.dumps(
                {
                    "success": result.success,
                    "waves_completed": result.waves_completed,
                    "total_waves": result.total_waves,
                    "components": [cr.__dict__ for cr in result.component_results],
                },
                indent=2,
                sort_keys=True,
            )
        )
    else:
        verb = "Dry-run" if dry_run else "Deployment"
        print(f"\n{verb} {'SUCCEEDED' if result.success else 'FAILED'}")
        print(f"Waves completed: {result.waves_completed}/{result.total_waves}")
        for cr in result.component_results:
            status_text = "OK" if cr.success else "FAILED"
            error_str = f" - {cr.error}" if cr.error else ""
            print(f"  {cr.component}: {status_text} ({cr.duration:.1f}s){error_str}")

    return 0 if result.success else 1


def cmd_status(args: argparse.Namespace) -> int:
    """Report release and gate health without mutating the cluster."""
    from .cluster import results_json, smoke, status

    config = load_config(args.file)
    namespace = args.namespace or config.defaults.namespace
    results = status(
        config,
        namespace,
        args.kube_context,
        args.kubeconfig,
    )
    results.extend(smoke(config, namespace, args.kube_context, args.kubeconfig))
    _emit_check_results(results, args.output, results_json)
    return 1 if any(not result.healthy for result in results) else 0


def cmd_preflight(args: argparse.Namespace) -> int:
    from .cluster import preflight, results_json

    config = load_config(args.file)
    results = preflight(
        config,
        _repo_root(Path(args.file)),
        args.namespace or config.defaults.namespace,
        args.kube_context,
        args.kubeconfig,
    )
    _emit_check_results(results, args.output, results_json)
    return 0


def cmd_smoke(args: argparse.Namespace) -> int:
    from .cluster import results_json, smoke, status

    config = load_config(args.file)
    namespace = args.namespace or config.defaults.namespace
    results = status(config, namespace, args.kube_context, args.kubeconfig)
    results.extend(smoke(config, namespace, args.kube_context, args.kubeconfig))
    _emit_check_results(results, args.output, results_json)
    return 1 if any(not result.healthy for result in results) else 0


def cmd_cutover(args: argparse.Namespace) -> int:
    from .cutover import (
        apply_plan,
        create_plan,
        finalize_plan,
        rollback_plan,
    )

    config = load_config(args.file)
    root_dir = _repo_root(Path(args.file))
    namespace = args.namespace or config.defaults.namespace
    if args.cutover_command == "plan":
        path = create_plan(
            config,
            root_dir,
            args.artifact_dir or config.defaults.artifact_dir,
            namespace,
            args.kube_context,
            args.kubeconfig,
            _args_overrides(args),
            args.umbrella_release,
        )
        payload = json.loads(path.read_text())
        if args.output == "json":
            print(json.dumps({"plan": str(path), "digest": payload["digest"]}, indent=2))
        else:
            print(f"Cutover plan: {path}\nDigest: {payload['digest']}")
        return 0
    if args.cutover_command == "apply":
        apply_plan(
            config,
            root_dir,
            Path(args.plan),
            args.digest,
            args.confirm_context,
            args.confirm_release,
            args.traffic_drained,
            args.kubeconfig,
            _args_overrides(args),
        )
    elif args.cutover_command == "finalize":
        finalize_plan(
            config,
            Path(args.plan),
            args.digest,
            args.confirm_context,
            args.confirm_release,
            args.kubeconfig,
        )
    elif args.cutover_command == "rollback":
        rollback_plan(
            root_dir,
            Path(args.plan),
            args.digest,
            args.confirm_context,
            args.confirm_release,
            args.kubeconfig,
        )
    else:
        raise ValueError("cutover subcommand is required")
    print(f"Cutover {args.cutover_command} completed")
    return 0


def _repo_root(config_path: Path) -> Path:
    resolved = config_path.resolve()
    for candidate in [resolved.parent, *resolved.parents]:
        if (candidate / "helm" / "ssl-proxy").is_dir() and (candidate / "ops").is_dir():
            return candidate
    raise ValueError(f"Could not locate repository root from {config_path}")


def _args_overrides(args: argparse.Namespace) -> dict[str, Any]:
    return parse_overrides(args.set, args.set_string, args.set_literal)


def _selected_components(config: StackConfig, args: argparse.Namespace) -> list[str]:
    if not args.component and not args.from_wave:
        return list(config.components)
    return [
        name
        for wave in resolve_dependencies(
            config,
            target_component=args.component,
            from_wave=args.from_wave,
            include_descendants=args.include_descendants,
        )
        for name in wave
    ]


def _print_errors(errors: list[str], output: str) -> None:
    if output == "json":
        print(json.dumps({"valid": False, "errors": errors}, indent=2, sort_keys=True))
    else:
        print("Validation FAILED:", file=sys.stderr)
        for error in errors:
            print(f"  - {error}", file=sys.stderr)


def _emit_check_results(results: list[Any], output: str, serializer: Any) -> None:
    if output == "json":
        print(serializer(results))
    else:
        for result in results:
            marker = "OK" if result.healthy else "DEGRADED"
            print(f"{marker:8} {result.subject}: {result.detail}")


# ---------------------------------------------------------------------------
# CLI argument parser
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    """Build the argument parser."""
    parser = argparse.ArgumentParser(
        prog="stackctl",
        description="Stack deployment orchestrator",
    )

    subparsers = parser.add_subparsers(dest="command", help="Command to execute")

    # Shared flags available on every subcommand
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--file",
        default="stackctl/stack.yaml",
        help="Path to stack configuration file (default: stackctl/stack.yaml)",
    )
    common.add_argument(
        "--kube-context",
        help="Kubernetes context to use",
    )
    common.add_argument(
        "--kubeconfig",
        help="Path to kubeconfig file",
    )
    common.add_argument(
        "--namespace",
        help="Override default namespace",
    )
    common.add_argument(
        "--set",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set a value (can be repeated)",
    )
    common.add_argument(
        "--set-string",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set a string value (can be repeated)",
    )
    common.add_argument(
        "--set-literal",
        action="append",
        default=[],
        metavar="KEY=VALUE",
        help="Set a literal value (can be repeated)",
    )
    common.add_argument(
        "--component",
        help="Target a specific component (includes its dependencies)",
    )
    common.add_argument(
        "--from-wave",
        type=int,
        help="Start deployment from a specific wave number",
    )
    common.add_argument(
        "--include-descendants",
        action="store_true",
        help="Include descendants when targeting a component",
    )
    common.add_argument(
        "--output",
        choices=("text", "json"),
        default="text",
        help="Output format",
    )
    common.add_argument(
        "--artifact-dir",
        help="Repository-rooted artifact directory",
    )
    common.add_argument(
        "--max-parallel",
        type=int,
        help="Maximum sibling deployments (default from stack config)",
    )
    common.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose output",
    )

    subparsers.add_parser("plan", parents=[common], help="Print the deployment plan")
    subparsers.add_parser("validate", parents=[common], help="Validate configuration")
    subparsers.add_parser("render", parents=[common], help="Render split releases")
    subparsers.add_parser("compare", parents=[common], help="Compare umbrella and split renders")
    subparsers.add_parser("preflight", parents=[common], help="Check cluster prerequisites")
    subparsers.add_parser("dry-run", parents=[common], help="Dry-run deployment")

    deploy_parser = subparsers.add_parser("deploy", parents=[common], help="Deploy components")
    deploy_parser.add_argument(
        "--keep-artifacts",
        action="store_true",
        help="Retain effective-values and diagnostic files even on success",
    )
    deploy_parser.add_argument(
        "--work-dir",
        help="Explicit working directory for artifacts (overrides auto-generated run dir)",
    )

    subparsers.add_parser("status", parents=[common], help="Show deployment status")
    subparsers.add_parser("smoke", parents=[common], help="Run status and application checks")

    cutover = subparsers.add_parser("cutover", help="Guarded Helm ownership migration")
    cutover_sub = cutover.add_subparsers(dest="cutover_command")
    cutover_plan = cutover_sub.add_parser("plan", parents=[common], help="Create a UID-bound plan")
    cutover_plan.add_argument("--umbrella-release", default="ssl-proxy")

    def add_guarded_arguments(command: argparse.ArgumentParser, *, drain: bool = False) -> None:
        command.add_argument("--plan", required=True, help="Saved cutover plan.json")
        command.add_argument("--digest", required=True, help="Confirmed plan digest")
        command.add_argument("--confirm-context", required=True)
        command.add_argument("--confirm-release", required=True)
        if drain:
            command.add_argument(
                "--traffic-drained",
                action="store_true",
                help="Assert required traffic draining is complete",
            )

    cutover_apply = cutover_sub.add_parser("apply", parents=[common], help="Adopt split ownership")
    add_guarded_arguments(cutover_apply, drain=True)
    cutover_finalize = cutover_sub.add_parser(
        "finalize", parents=[common], help="Remove stale umbrella Helm records"
    )
    add_guarded_arguments(cutover_finalize)
    cutover_rollback = cutover_sub.add_parser(
        "rollback", parents=[common], help="Restore umbrella ownership"
    )
    add_guarded_arguments(cutover_rollback)

    return parser


COMMANDS = {
    "plan": cmd_plan,
    "validate": cmd_validate,
    "render": cmd_render,
    "compare": cmd_compare,
    "preflight": cmd_preflight,
    "dry-run": cmd_dry_run,
    "deploy": cmd_deploy,
    "status": cmd_status,
    "smoke": cmd_smoke,
    "cutover": cmd_cutover,
}


def main(argv: list[str] | None = None) -> int:
    """Main entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 1

    handler = COMMANDS.get(args.command)
    if handler is None:
        print(f"Unknown command: {args.command}", file=sys.stderr)
        return 1

    try:
        return handler(args)
    except (FileNotFoundError, ValueError, RuntimeError) as exc:
        if getattr(args, "output", "text") == "json":
            print(json.dumps({"error": str(exc)}, indent=2), file=sys.stderr)
        else:
            print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
