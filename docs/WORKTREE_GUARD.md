# Worktree overlap and conflictsWith

`wellmanifest/ticket-lifecycle` owns bounded ticket intent. Parallel
worktrees are legal only when write scopes do not collide.

## Rule

If `git worktree list` (or a sibling `.worktrees` directory in the same
organization folder) shows two `IN_PROGRESS` tickets for the same repository:

- `allowedPaths` must be disjoint, **or**
- each intent lists the other ticket in `conflictsWith`, and only one of
  those tickets remains in an implementation state.

The adopted checker is `worktree-guard.yaml` from `wellmanifest/new-project`.
Finding `GOV-WORKTREE-OVERLAP-002` means the intents are missing that
declaration. `edit` / `validate` stay unauthorized until the overlap is
narrowed or serialized.

`dependsOn` is not a substitute for `conflictsWith`. A dependency orders
tickets; a conflict forbids them from writing the same paths at once.

## Scope of the comparison

The gate answers for **this repository identity only**. Discovery still walks
the whole workspace, but two `IN_PROGRESS` tickets in different repositories
never contend for the same write reservation, so only same-identity checkouts
are compared. `worktree_guard.py` selects that scope automatically when
`--root` is a checkout.

`TODO.md`, `project/TICKETS.md` and `project/ticket-*/**` are excluded from the
comparison: every intent declares them, so including them would make every pair
of active tickets overlap and the rule would carry no signal. A ticket counts
only in the worktree whose **branch** is that ticket's branch, so a
merged-but-open ticket directory copied into sibling worktrees is not a second
claimant.

## Install

```bash
./scripts/install-worktree-guard.sh --target /path/to/repo
python3 /path/to/repo/.governance/worktree_guard.py --root /path/to/repo --once
```

Normative detail: `wellmanifest/new-project` `docs/WORKTREE_GUARD.md`.
