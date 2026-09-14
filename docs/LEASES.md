# Ticket execution leases

Contract version: `wellmanifest.ticket-execution-lease/v1`.

`wellmanifest.ticket-execution-lease/v1` is the canonical handoff contract for
an agent that is actively editing a ticket worktree. It is a coordination
record, not a Git lock and not merge authority.

## Timing and ownership

An acquired lease has a 3600-second TTL. `leaseExpiresAt` is calculated from
the last accepted renewal, and `takeoverAt` is exactly 600 seconds after that
expiry. The controller's authenticated UTC clock is authoritative; agents do
not extend a lease by changing a local file or by reporting process activity.

The owner may renew before `takeoverAt`, including during the grace period.
Renewal requires the exact `leaseId`, `generation` and `fencing` values. A
renewal changes all three monotonic values and recalculates the next expiry.
The owner may release an active lease. A release is terminal for that lease.

## Safe takeover

At or after `takeoverAt`, another authorized agent may submit `takeover` with
the exact current generation and fencing values plus its own actor, session and
worktree identity. The controller atomically changes the owner and increments
both monotonic values. Any write carrying the old generation or fencing value
is rejected, which prevents a paused or partitioned agent from writing after
handoff.

Early takeover, wrong-owner renewal/release, stale compare-and-swap values,
partial new-owner identity and malformed timestamps fail closed. Process
presence, IDE activity, queue state, elapsed time observed by an agent, a dirty
checkout or an absent heartbeat is evidence for inspection only; none grants
takeover authority.

## Required operation sequence

1. The controller creates one lease bound to repository, ticket, workstream,
   branch, worktree, scope hash and current head.
2. The executing agent keeps the lease alive with conditional `renew`
   requests. A checkpoint should include the current generation and fencing.
3. Before every mutating worktree operation, the runtime re-reads the lease and
   verifies the owner session, generation and fencing. Read-only observation may
   continue without ownership.
4. After `takeoverAt`, a replacement agent obtains a fresh takeover receipt,
   then re-observes the checkout and its dirty content before writing.
5. The old agent must stop on a rejected request. It may not retry with guessed
   counters or overwrite the lease record.
6. On merge, cancellation or explicit completion, the protected controller
   records the terminal receipt and releases the worktree separately.

The standard validator is dependency-free:

```bash
python3 standard/lease_conformance.py --all
```

`git-lifecycle` owns the adapter that turns the fencing value into a worktree
write guard. It must consume this contract rather than implement a second
expiry or takeover clock.
