# Ticket 001: Define standalone ticket lifecycle standard

- **ID**: ticket-001
- **Owner**: unresolved:human
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-08-12

## Goal and scope

Extract the ticket lifecycle module into an independently versioned local
repository. Define allocation, bounded intent, session authorization, editing,
validation, publication, blocking, resumption and governance-only closure as a
closed typed state machine.

## Acceptance criteria

- [x] AC-01: The repository has an immutable published governance adoption and
  a real local seed baseline created before implementation.
- [x] AC-02: A closed Draft 2020-12 schema defines request, state and receipt.
- [x] AC-03: Request-only GBNF excludes shell, argv, paths, URLs and secrets.
- [x] AC-04: Documentation separates session authorization from trusted merge,
  defines workstream release and exact integration closure.
- [x] AC-05: Positive and adversarial conformance passes locally and in
  networkless, read-only Docker.
- [x] AC-06: Governance and diff hygiene pass against the exact baseline.

## Authorization

The request to continue and extract this module as a new repository creates
`SESSION_EXECUTION_AUTHORIZATION` and the narrow autonomous seed-baseline
authorization. It allows exactly one local governance-only baseline commit
while `HEAD` is unborn and implementation is absent. It does not authorize a
remote, push, PR, merge, tag or release.

The subsequent explicit request to push the changes separately authorizes
creation of the public repository, committing this bounded implementation,
pushing its ticket branch and opening a pull request. It does not authorize a
direct push to `main`, merge, tag or release creation.

## Baseline

The local seed transaction passed and created
`dd80fc8e2b33ef0133e104a4b97329d69a64c3a9`. Standard implementation begins
after this SHA and bounded delivery uses it as the exact accepted base.

## Participants

- Human participant: unresolved; no `user-*` file was created.
- Agent participant: [ai-codex.md](ai-codex.md)

## Publication validation

Host and networkless Docker conformance both passed with three positive
documents and eight adversarial rejections. Governance passed with zero errors
and warnings, and diff hygiene passed. Trusted exact-head review and merge
remain pending after ticket-branch publication.
