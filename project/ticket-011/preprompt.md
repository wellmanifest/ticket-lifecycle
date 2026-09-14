Define a portable execution-lease contract for ticket agents. The owner holds
the lease for 3600 seconds; takeover becomes eligible only 600 seconds after
expiry. Require controller time, compare-and-swap generation, and fencing so a
stale agent cannot write after takeover. Do not add runtime or merge authority.
