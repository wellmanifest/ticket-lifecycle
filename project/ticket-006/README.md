# Ticket 006: Add resumable work checkpoint transition

- **ID**: ticket-006
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-09-01

## Goal and scope

Add a non-state-changing `checkpoint` transition to active ticket states. The
transition binds exactly one external `new-project.work-continuity/v1` receipt,
keeps the workstream reserved and grants no authorization. Resume remains a
separate operation that revalidates live state and authority.

## Acceptance criteria

- [x] AC-01: Schema, grammar and Lifecycle DSL expose the same checkpoint
  self-transitions for authorized, editing, validating, publication and
  blocked states.
- [x] AC-02: A checkpoint request and applied receipt require exactly one
  bounded continuity receipt and reject state movement or scope release.
- [x] AC-03: Documentation explains mandatory checkpoint boundaries and the
  observe-first, fail-closed resume rule in `docs/WORK_CONTINUITY.md`.
- [x] AC-04: Standalone conformance and repository governance pass.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)

## Resolved prerequisite

`new-project` 0.19.19 was published and adopted by protected merge receipt
`receipt:github-pr:wellmanifest/ticket-lifecycle:9`. The branch was rebased onto
merge commit `bce6b0245447a9a74348d7e9664d5038864d3798` after a secret-scanned,
content-addressed checkpoint of its dirty ticket state.
