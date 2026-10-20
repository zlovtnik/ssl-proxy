# Atheros Search advisory plans

This directory holds review and implementation workmaps that are independent of
the in-progress Atheros reporting plans in [`plans/`](../plans/README.md).

| Priority | Plan | Dependency | Status | Scope |
| --- | --- | --- | --- | --- |
| P0/P1 first | [001: Search performance and quality workmap](001-atheros-search-performance-quality-workmap.md) | Reconcile the dirty Integration Console worktree; establish a fixed baseline | READY FOR EXECUTION | Audit of the 21 numbered recommendations, backend quality rules, verification, and rollout |
| P0/P1 staged | [002: Proxy-only RAG and ML workmap](002-proxy-rag-ml-workmap.md) | Fresh coverage measurements; versioned evidence contracts; explicit proxy scopes | PLANNED | Eight-stage tasklist for normalization, evidence, reconciliation, bounded recovery, behavior, retrieval, evaluation and GitOps release |

The workmap is a plan, not a claim that its proposed changes have been made.
Executors must recheck the recorded source state and preserve unrelated edits.
