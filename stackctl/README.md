# stackctl

Stack deployment orchestrator for the ssl-proxy project.

## Overview

`stackctl` manages the deployment of multiple Kubernetes components with dependency resolution, readiness gates, and wave-based execution ordering.

## Usage

```bash
# Print the deployment plan
python3 stackctl/stackctl.py plan

# Validate configuration
python3 stackctl/stackctl.py validate

# Deploy all components
python3 stackctl/stackctl.py deploy

# Deploy a specific component (and its dependencies)
python3 stackctl/stackctl.py deploy --component atheros-search

# Deploy starting from a specific wave
python3 stackctl/stackctl.py deploy --from-wave 4
```

## Configuration

The stack configuration lives in `stackctl/stack.yaml`. It defines:

- **Component types**: `helm`, `helm-job`, `manifest`, `external-check`
- **Dependencies**: Which components must be deployed first
- **Gates**: Kubernetes resources to wait for before proceeding
- **Values**: Helm values files and overrides

## Component Types

| Type | Purpose |
|------|---------|
| `helm` | Deploy long-running workloads |
| `helm-job` | Deploy a Job that must execute for this deployment |
| `manifest` | Apply raw Kubernetes manifests |
| `external-check` | Verify an externally managed dependency |

## Development

```bash
# Install dependencies
pip install -r stackctl/requirements.txt

# Run tests
pytest stackctl/tests/
```
