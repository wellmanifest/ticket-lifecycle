# Ticket 001: Define standalone ticket lifecycle standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: PLAN
- **Created**: 2026-08-12

## Goal and scope

Extract the ticket lifecycle module into an independently versioned local
repository. Define allocation, bounded intent, session authorization, editing,
validation, publication, blocking, resumption and governance-only closure as a
closed typed state machine.

## Acceptance criteria

- [ ] AC-01: The repository has an immutable published governance adoption and
  a real local seed baseline created before implementation.
- [ ] AC-02: A closed Draft 2020-12 schema defines request, state and receipt.
- [ ] AC-03: Request-only GBNF excludes shell, argv, paths, URLs and secrets.
- [ ] AC-04: Documentation separates session authorization from trusted merge,
  defines workstream release and exact integration closure.
- [ ] AC-05: Positive and adversarial conformance passes locally and in
  networkless, read-only Docker.
- [ ] AC-06: Governance and diff hygiene pass against the exact baseline.

## Authorization

The request to continue and extract this module as a new repository creates
`SESSION_EXECUTION_AUTHORIZATION` and the narrow autonomous seed-baseline
authorization. It allows exactly one local governance-only baseline commit
while `HEAD` is unborn and implementation is absent. It does not authorize a
remote, push, PR, merge, tag or release.

## Participants

- Human participant: unresolved; no `user-*` file was created.
- Agent participant: [ai-codex.md](ai-codex.md)
