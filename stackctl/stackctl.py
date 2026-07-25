#!/usr/bin/env python3
"""stackctl - Stack deployment orchestrator.

Phase 1: Configuration parsing and dependency graph planning.
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from collections import defaultdict
from pathlib import Path
from typing import Annotated, Any

import yaml
from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Supported component types
# ---------------------------------------------------------------------------

COMPONENT_TYPES = frozenset({"helm", "helm-job", "manifest", "external-check"})


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class Gate(BaseModel):
    """A readiness gate for a component."""

    resource: str | None = None
    discover: dict[str, str] | None = None
    condition: str | None = None

    @field_validator("discover")
    @classmethod
    def validate_discover(cls, v: dict[str, str] | None) -> dict[str, str] | None:
        if v is not None and "kind" not in v:
            raise ValueError("discover must contain a 'kind' key")
        return v


class JobConfig(BaseModel):
    """Job-specific configuration for helm-job components."""

    rerun: str = "replace"


class Component(BaseModel):
    """A single deployable component."""

    type: str
    release: str
    chart: str | None = None
    values_key: str | None = None
    include_global: bool = False
    set: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)
    gates: list[Gate] = Field(default_factory=list)
    job: JobConfig | None = None
    timeout: str | None = None
    rollback_on_failure: bool = False

    @field_validator("type")
    @classmethod
    def validate_type(cls, v: str) -> str:
        if v not in COMPONENT_TYPES:
            raise ValueError(
                f"Invalid component type '{v}'. Must be one of: {', '.join(sorted(COMPONENT_TYPES))}"
            )
        return v


class Defaults(BaseModel):
    """Default settings applied to all components."""

    namespace: str = "default"
    timeout: str = "10m"
    values: list[str] = Field(default_factory=list)


class StackConfig(BaseModel):
    """Root configuration model."""

    version: int
    defaults: Defaults = Field(default_factory=Defaults)
    components: dict[str, Component] = Field(default_factory=dict)

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

    for name, component in config.components.items():
        # Check that all dependencies exist
        for dep in component.depends_on:
            if dep not in known_components:
                errors.append(
                    f"Component '{name}' depends on unknown component '{dep}'"
                )

        # helm and helm-job types require a chart
        if component.type in ("helm", "helm-job") and not component.chart:
            errors.append(
                f"Component '{name}' of type '{component.type}' requires a 'chart' field"
            )

        # helm-job requires job config
        if component.type == "helm-job" and not component.job:
            errors.append(
                f"Component '{name}' of type 'helm-job' requires a 'job' configuration"
            )

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
        ready = sorted(
            [n for n in remaining if in_degree[n] == 0]
        )
        if not ready:
            # All remaining nodes have unsatisfied deps — shouldn't happen
            # if cycles were detected earlier
            raise ValueError(
                f"Circular dependency detected among: {sorted(remaining)}"
            )
        waves.append(ready)
        for node in ready:
            remaining.remove(node)
            # Decrease in-degree for all nodes that depend on this one
            adjacency = build_adjacency(config)
            for dependent in adjacency.get(node, []):
                if dependent in remaining:
                    in_degree[dependent] -= 1

    return waves


def resolve_dependencies(
    config: StackConfig,
    target_component: str | None = None,
    from_wave: int | None = None,
) -> list[list[str]]:
    """Resolve the deployment plan, optionally targeting a specific component.

    When target_component is specified, includes the target and all
    transitive dependencies.
    """
    all_waves = topological_sort_waves(config)

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

        # Filter waves to only include required components
        filtered_waves = []
        for wave in all_waves:
            filtered = [c for c in wave if c in required]
            if filtered:
                filtered_waves.append(filtered)
        return filtered_waves

    if from_wave is not None:
        if from_wave < 1 or from_wave > len(all_waves):
            raise ValueError(
                f"Invalid from_wave {from_wave}. Valid range: 1-{len(all_waves)}"
            )
        return all_waves[from_wave - 1 :]

    return all_waves


# ---------------------------------------------------------------------------
# Effective values generation
# ---------------------------------------------------------------------------


def deep_merge(base: dict, override: dict) -> dict:
    """Deep merge two dictionaries. Override values take precedence."""
    result = base.copy()
    for key, value in override.items():
        if (
            key in result
            and isinstance(result[key], dict)
            and isinstance(value, dict)
        ):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def generate_effective_values(
    config: StackConfig,
    component_name: str,
    umbrella_values: list[dict[str, Any]],
    runtime_overrides: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Generate effective values for a component.

    1. Merge umbrella values files in order
    2. Extract component's values_key section
    3. Optionally include global block
    4. Apply runtime overrides
    """
    component = config.components[component_name]

    # Merge all umbrella values files in order
    merged: dict[str, Any] = {}
    for values_file in umbrella_values:
        merged = deep_merge(merged, values_file)

    # Extract component-specific values
    effective: dict[str, Any] = {}
    if component.values_key and component.values_key in merged:
        effective = merged[component.values_key].copy()

    # Include global block if requested
    if component.include_global and "global" in merged:
        effective["global"] = merged["global"].copy()

    # Apply component-level set overrides
    if component.set:
        effective = deep_merge(effective, component.set)

    # Apply runtime overrides
    if runtime_overrides:
        effective = deep_merge(effective, runtime_overrides)

    return effective


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
        config, target_component=args.component, from_wave=args.from_wave
    )

    print(f"Stack Plan ({len(config.components)} components, {len(waves)} waves)\n")

    for i, wave in enumerate(waves, 1):
        print(f"Wave {i}")
        for comp_name in wave:
            comp = config.components[comp_name]
            deps = f" (depends: {', '.join(comp.depends_on)})" if comp.depends_on else ""
            print(f"  {comp_name} [{comp.type}]{deps}")
        print()

    if args.verbose:
        print("Configuration Details:")
        print(f"  Namespace: {config.defaults.namespace}")
        print(f"  Timeout: {config.defaults.timeout}")
        print(f"  Values files: {len(config.defaults.values)}")
        for vf in config.defaults.values:
            print(f"    - {vf}")

    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    """Validate configuration without accessing Kubernetes."""
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

    print(f"Validation PASSED ({len(config.components)} components)")

    if args.verbose:
        waves = topological_sort_waves(config)
        for i, wave in enumerate(waves, 1):
            print(f"  Wave {i}: {', '.join(wave)}")

    return 0


def cmd_dry_run(args: argparse.Namespace) -> int:
    """Dry-run deployment (Phase 4 placeholder)."""
    print("dry-run is not yet implemented (Phase 4)")
    return 0


def cmd_deploy(args: argparse.Namespace) -> int:
    """Deploy components (Phase 6 placeholder)."""
    print("deploy is not yet implemented (Phase 6)")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Show deployment status (Phase 5 placeholder)."""
    print("status is not yet implemented (Phase 5)")
    return 0


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
        "--verbose", "-v",
        action="store_true",
        help="Enable verbose output",
    )

    subparsers.add_parser("plan", parents=[common], help="Print the deployment plan")
    subparsers.add_parser("validate", parents=[common], help="Validate configuration")
    subparsers.add_parser("dry-run", parents=[common], help="Dry-run deployment")
    subparsers.add_parser("deploy", parents=[common], help="Deploy components")
    subparsers.add_parser("status", parents=[common], help="Show deployment status")

    return parser


COMMANDS = {
    "plan": cmd_plan,
    "validate": cmd_validate,
    "dry-run": cmd_dry_run,
    "deploy": cmd_deploy,
    "status": cmd_status,
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

    return handler(args)


if __name__ == "__main__":
    sys.exit(main())
