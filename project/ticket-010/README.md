# Ticket 10: Express lifecycle document fences as valid Policy DSL

- **ID**: ticket-010
- **Owner**: unresolved:human
- **Status**: IN_PROGRESS
- **Workflow state**: EDIT
- **Created**: 2026-09-13

## Goal and scope

SESSION_EXECUTION_AUTHORIZATION: on 2026-09-13 the user asked to correct
Wellmanifest standards that contain errors or do not express their logic in the
DSL standard used by `wellmanifest/new-project/CONTRIBUTING.md`.

A `dsl` fence with a concrete `DOCUMENT` header is a Policy DSL carrier
(`wellmanifest/policy-dsl` spec 3.2). In this repository:

- the header fence carries `SCHEMA` and `REQUEST_GRAMMAR` statements that Policy DSL v1 does not define, so `validate-markdown` fails at line 5;
- `TRANSITION ... ACTION ...` is not a Policy DSL transition and `ACTIVE_NONTERMINAL -> blocked` references an undeclared state;
- `publication -> done` omits the trusted-integration guard that the prose and state diagram require;
- the authorization-class bindings end a line with `=` and therefore are not parseable multi-line expressions.

Declares schema and grammar as bindings, rewrites transitions as `TRANSITION a -> b WHEN ACTION = x` with the six explicit block edges and the edit/close guards from the prose, parenthesizes the authorization expressions and adds rules TICKET-AUTH-001/002 for session versus separate authority. Document version 2 -> 3.

Non-goals: no schema, grammar, blueprint, conformance code or diagnostic code
change; prose, tables and diagrams stay as explanation of the same contract.

## Acceptance criteria

- [ ] AC-01: `python3 tests/policy_dsl_check.py validate-markdown` from
  `wellmanifest/policy-dsl@48e95c8` accepts every changed document.
- [ ] AC-02: The fail-closed carrier selector published in
  `wellmanifest/policy-dsl@d723271` (PR #22) and the checker pinned by
  `wellmanifest/new-project` (`daaf7b7`) also accept every changed document.
- [ ] AC-03: The DSL projection matches the existing prose, diagrams and
  machine artifacts; the repository governance gate passes.

Cross-repository evidence:
`subactor/docs/architecture/analysis/semcod-library-quality.md`.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
