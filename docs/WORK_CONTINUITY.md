# Work continuity in the ticket lifecycle

Conversation context is a cache, not durable task state. The ticket lifecycle
therefore exposes `checkpoint` as an append-only, same-state transition for
`authorized`, `editing`, `validating`, `publication` and `blocked`. A request
and its applied receipt contain exactly one opaque
`receipt:continuity.<id>` reference to a validated
`new-project.work-continuity/v1` document.

The transition does not renew authorization or a lease, release the workstream,
move the ticket, complete an effect or carry source data. The external receipt
binds the ticket, intent and scope digests, exact Git state, workspace digest,
criteria and pending effects. Conversation prose, raw logs, patches, secrets
and host paths stay outside the lifecycle document.

## Checkpoint boundaries

Create a checkpoint after a bounded intent is accepted, at material milestones,
at the configured interval, before context compaction or handoff, when pausing
or blocking, after tool failure that leaves useful work, and immediately before
and after each push, PR, validation, merge or release effect. Dirty work is
durable only after an authorized ticket-branch commit or a content-addressed,
externally stored and secret-scanned snapshot.

## Resume

Resume observes the filesystem, Git, PRs and protected receipts first. It then
verifies the append-only checkpoint chain, repository and ticket identity,
intent/scope digests, `HEAD`, workspace digest and any pending idempotency key.
Authorization, lease revision and fencing token are revalidated separately;
the checkpoint itself grants no authority.

When observed state diverges, preserve both versions and route to reconciliation
or `blocked`. Never reset, overwrite, restore a snapshot, mark an effect done or
release scope merely because a checkpoint says that an older state existed.
