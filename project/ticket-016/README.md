# Ticket 016: Use a non-tmp absolute path in the split-plan negative fixture

- **ID**: ticket-016
- **Owner**: claude
- **Status**: DONE
- **Workflow state**: DONE
- **Created**: 2026-11-04

## Goal and scope

The `absolute-path` negative case in `standard/split_plan.py::self_test` used the
literal `/tmp/work`. `wellman check` (`GOV-NOHARDCODE-TMP-LEAK`) flags that literal
in every adopter's managed copy, where it cannot be edited locally (observed in
maskservice/c2004: the only remaining error after wellmanifest/wellman PR #89).
The case only needs any absolute path: `scopePath` in
`standard/split-plan.schema.json` rejects everything starting with `/`.

Change exactly that one literal to `/work`. No schema, grammar or digest changes.

## Acceptance criteria

- [x] AC-01: `python3 standard/split_plan.py --self-test` output is byte-identical
  before and after, and the `absolute-path` case is still rejected.
- [x] AC-02: `./project/governance-check.sh` and `wellman check` pass.

## Tracking boundary

This directory contains the minimal reviewed intent. Optional participant prose
and raw command logs are not required delivery output.
