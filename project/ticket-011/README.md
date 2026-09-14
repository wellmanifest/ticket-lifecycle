# Ticket 011: Define expiring execution leases and safe ticket takeover

- **ID**: ticket-011
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: VALIDATION
- **Created**: 2026-09-14

## Goal and scope

`SESSION_EXECUTION_AUTHORIZATION`: the owner requested an interoperable lease
for the agent currently executing a ticket. The lease protects the ticket and
its worktree for 3600 seconds, then adds a 600-second grace period. A different
agent may take over only at `takeoverAt`, with a fresh compare-and-swap
generation and fencing value. The old agent must be rejected after takeover.

`ticket-lifecycle` owns the semantic contract. `git-lifecycle` will consume it
to fence worktree writes in a separately scoped adapter change.

## Acceptance criteria

- [x] AC-01: Scope is approved by a human owner through the request recorded above.
- [x] AC-02: Lease schema and grammar define a 3600-second lease and a 600-second takeover grace period without relying on local wall-clock guesses.
- [x] AC-03: Conformance accepts owner renewal before takeover and rejects stale renewal, early takeover, wrong owner, and stale fencing after takeover.
- [x] AC-04: Documentation defines the operational acquire/renew/takeover/release protocol and its fail-closed boundaries.

Validation evidence: `python3 standard/lease_conformance.py --all`,
`python3 standard/conformance.py --all`, `./project/governance-check.sh
--base origin/main --head HEAD --actor agent` and `git diff --check` pass.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
