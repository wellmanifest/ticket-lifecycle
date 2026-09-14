# ai-claude — ticket-010

- **participant-id**: ai-claude
- **role**: agent
- **ticket**: ticket-010

## Plan

1. Rewrite the header, state-machine and authorization fences of
   `docs/ARCHITECTURE.md` as Policy DSL v1 without changing the contract.
2. Validate with `wellmanifest/policy-dsl` `validate-markdown` at `48e95c8`
   and with the selector proposed in `wellmanifest/policy-dsl#22`.
3. Run the repository governance gate.

## Report

Policy DSL checkers daaf7b7, 48e95c8 and d723271 accept the document: 9 states, 14 transitions, 4
bindings, 2 rules. No schema, grammar or conformance file changed.
