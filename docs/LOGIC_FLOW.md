# Ticket lifecycle logic flow

```mermaid
sequenceDiagram
    participant M as Model / caller
    participant P as GBNF parser
    participant V as Schema + policy gate
    participant C as URI Process / CQRS controller
    participant T as Ticket store
    participant R as Receipt store
    M->>P: typed transition request
    P->>V: closed AST
    V->>V: resolve intent, state, authorization and evidence refs
    V->>C: one authorized transition
    C->>T: compare-and-set ticket state
    T-->>C: observed state
    C->>R: redacted idempotent receipt
    R-->>M: receipt reference
```

Allocation is performed by the managed clone-wide allocator; a request cannot
choose the ticket number. Planning binds a real Git baseline, scope, budgets and
validation evidence. Session authorization permits work only inside that
intent. Publication stops at a reviewable PR, while `done` requires separately
resolved trusted merge and post-merge evidence.

`block` releases the workstream and write reservation while preserving context.
`resume` revalidates the base, dependencies, scope and workspace before editing.
State mismatch, missing evidence, overlap, an unknown reference or fields
outside the schema reject before repository mutation.
