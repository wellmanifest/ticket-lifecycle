# Ticket 008: Define split-plan lifecycle for oversized in-progress work

- **ID**: ticket-008
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-09-01

## Goal and scope

Publish a closed `wellmanifest.split-plan/v1` contract for streaming an
already-working material slice from an oversized ticket while allocating the
remaining DAG to bounded successor tickets. The contract records only typed,
repository-relative scope and opaque evidence references; it grants neither
tool authority nor trusted merge approval.

## Acceptance criteria

- [x] AC-01: A split plan binds its plan reference, parent ticket, stable slice
  ID and exact accepted-base, head and checkpoint commits.
- [x] AC-02: The completed slice contains at least one material path outside
  process carriers and binds validation, snapshot and secret-scan receipts.
- [x] AC-03: Every successor binds an allocator receipt, bounded disjoint
  allowed paths, dependencies, conflicts and integration ownership.
- [x] AC-04: Terminal child receipts deterministically remove completed nodes
  from the resumable DAG and make replay/deduplication stable.
- [x] AC-05: Schema, strict grammar, semantic conformance, adversarial cases and
  repository governance pass on the exact implementation head.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
