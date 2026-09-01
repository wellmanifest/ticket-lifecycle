# Streaming an oversized ticket

`wellmanifest.split-plan/v1` separates a publishable material slice from the
remaining work without treating conversation history or ticket prose as
runtime state. It is an inert NL-to-DSL boundary: an LLM may propose the JSON
AST, but deterministic schema and semantic validation decide whether a
controller may resolve its opaque references. The document itself cannot run a
tool, allocate a ticket, create a worktree, push, merge or renew authority.

## When to split

The controller requests a split when an active ticket exceeds its declared
time, file, component, interface or dependency budget; discovers material
scope outside its intent; becomes too large for one independently testable
review; or cannot resume without mixing unrelated work. A power loss alone is
not a reason to split: first evaluate the checkpoint and snapshot. Split only
when the recovered scope is still oversized or contains separable outcomes.

## Safe sequence

1. Freeze the parent ticket's exact accepted base, current head and checkpoint
   commit. Persist its full session under the ignored repository-local
   `.subactor/` store and create a content-addressed snapshot only after a
   successful secret scan.
2. Identify a completed slice with material files outside `TODO.md`, ticket
   directories, indexes, registries and session carriers. Bind validation and
   material artifact receipts to that slice.
3. Compile the remaining outcome into a bounded acyclic graph. Allocate every
   successor through the protected allocator and bind its returned ticket and
   allocation receipt; a model never invents either.
4. Give the completed slice and every successor pairwise-disjoint restricted
   `allowedPaths`. Declare dependencies, symmetric conflicts and at most one
   integration owner. The owner coordinates shared integration but gains no
   path ownership implicitly.
5. Validate the canonical plan, then create each successor worktree through
   the Worktrees v4 tool boundary at
   `<primary-repository>/worktrees/<ticket>--<slug>`. The split DSL never
   carries absolute host paths.
6. Publish the completed material slice through exact-head validation. Do not
   create a parent PR containing only a plan, ticket status, index or log.
7. On every recovery pass, subtract only successors whose protected terminal
   receipt is present. A `done` label or stale prose without that receipt does
   not deduplicate or release work.

The order matters: allocation receipts prevent duplicate successor tickets;
the parent checkpoint prevents losing uncommitted work; disjoint scope permits
parallel agents; and terminal-receipt subtraction makes repeated recovery
idempotent.

## Closed document

The JSON Schema and strict GBNF profile fix property order and vocabulary. The
semantic validator additionally requires sorted unique arrays, unique node and
allocation receipts, an acyclic dependency graph, symmetric conflicts,
consistent integration ownership and pairwise-disjoint scope. Relative paths
allow only literal repository paths or a terminal `/**` subtree marker; no
absolute path, traversal or general glob expression is accepted.

A successor is terminal only when `state=done` and `terminalReceiptRef` is
present. All other states must have a null terminal receipt. The deterministic
pending projection removes terminal nodes and edges to them, exposing the
remaining DAG plus a canonical plan digest for replay detection.

## Composition boundaries

- `wellmanifest/new-project` owns ignored `.subactor` continuity storage,
  checkpoint validation and secret-scanned snapshot receipts.
- `wellmanifest/worktrees` owns repository-local relative worktree placement.
- `wellmanifest/git-lifecycle` owns account/fork/remote rebind, commit, push,
  superseding PR and terminal merge receipts.
- Subactor Strategy owns compilation and interpretation; its LLM and tool
  adapters receive validated ASTs and grants, never raw prose authority.

Changing GitHub accounts therefore does not change the split plan. A recovery
controller resolves the same repository, plan, ticket and commit bindings,
then delegates remote rebinding to `git-lifecycle` and records its opaque
receipt. Secrets, credential identifiers, remote URLs, commands and provider
payloads stay outside this contract.
