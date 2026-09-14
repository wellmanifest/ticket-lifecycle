# Agent plan — ticket-011

The user explicitly authorized implementation. The lease is deliberately
controller-evaluated: timestamps are supplied by the authority, renewal uses
the current owner and exact CAS values, and takeover increments the fence so a
paused agent cannot write after ownership changes.

Implementation is limited to the new standard contract and its guidance. No
runtime scheduler, GitHub operation, merge, branch deletion or secret access
is part of this ticket.
