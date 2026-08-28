# Ticket 005: Eliminate repository ticket ceremony loops

- **ID**: ticket-005
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PUBLICATION
- **Created**: 2026-08-28

## Goal and scope

Remove the repository-writing lifecycle ceremony that turns one delivery into
plan, implementation and closure commits. Keep bounded intent and trusted
integration evidence, but make the intent atomic with the material change and
make the terminal transition an external receipt with no repository mutation.

## Acceptance criteria

- [x] AC-01: An applied close receipt releases the workstream.
- [x] AC-02: The standard states that merge completion is recorded outside the
  implementation checkout and does not require a closure commit or PR.
- [x] AC-03: Intent may be committed atomically with the first material change.
- [x] AC-04: Lifecycle conformance covers the terminal receipt invariant.

## Authorization

The user's request to investigate and repair Subactor ticket loops records
`SESSION_EXECUTION_AUTHORIZATION` for this bounded standard change.

## Participants

- Human participant: unresolved; no user-* file was created by this script.
- Agent participant: [ai-codex.md](ai-codex.md)
