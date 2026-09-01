# Ticket 007: Adopt continuity-aware new-project 0.19.19

- **ID**: ticket-007
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-09-01

## Goal and scope

Atomically adopt the published `wellmanifest/new-project` 0.19.19 governance
package at exact revision `43999c793a86084b4c3198fe07be350105db59ec`.
The upgrade makes protected terminal merge receipts and bounded work-continuity
checkpoints available to this repository without changing the ticket lifecycle
domain contract.

## Acceptance criteria

- [x] AC-01: The adoption lock identifies version 0.19.19, the published exact
  source revision and the complete generated managed-file projection.
- [x] AC-02: The continuity runtime, schema and diagnostic are installed from
  the immutable package rather than copied or locally forked.
- [x] AC-03: Domain files under `standard/**` remain unchanged.
- [x] AC-04: Adoption drift check and repository governance pass.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
