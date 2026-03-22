# Vilnius — Confidential Compute Monitoring System Prototype

This workspace now models CCM as an **append-only event log** plus a set of
**protocols** that read the log and emit more events into it.

## Core Concepts

- **Event log**: the only durable primitive. Source events, verification
  outcomes, capacity estimates, and disclosures all live in the same log.
- **Transcript**: a named view over the event log, not a storage type. In this
  prototype, the transcript means the events that describe use of the monitored
  compute.
- **Protocols**: components that read the current log, keep whatever ephemeral
  state they need locally, and emit downstream-relevant events.
- **Writers/readers**: each event instance declares who wrote it via
  `writer: Role` and who can read it via `readers: frozenset[Role]`.
- **Views**: each event type declares `.views`, which determines whether it
  belongs to the transcript, verification, or disclosure views.

## File Layout

- `event_log.py`: `Event`, `EventLog`, `Role`, `EventView`
- `ccm.py`: rack config types, protocol orchestration, summary rendering
- `protocols/`: protocol-local event types plus protocol logic
- `protocols/transparency/correctness/`: shared correctness events plus
  `reexecution.py` and `zero_knowledge.py`
- `tests/`: stdlib `unittest` coverage for the refactor

## Default Protocol Flow

`run_monitoring_cycle(...)` runs protocols in this order:

1. network consistency
2. correctness mechanism (reexecution or zero knowledge)
3. sanitization frequency
4. schedule coverage
5. model approval
6. covert capacity estimation
7. disclosure

Each protocol appends its output events to the same `EventLog`, so later
protocols can depend on earlier results.

## Current Scope

This is still a structural prototype. The check logic remains intentionally
simple in places. The main goal of the refactor is to make the architecture
explicit:

- no `Transcript` storage class
- no `CheckResult` or `TransparencyReport`
- all durable verification outputs represented as events

## Correctness Structure

Correctness now has one shared event surface and multiple mechanism-specific
control flows:

- shared transcript claim: `InferenceClaimedEvent`
- shared verifier outputs: `CorrectnessCheckRequestedEvent`,
  `CorrectnessCheckTimedOutEvent`, `CorrectnessEvaluatedEvent`
- reexecution mechanism: `reexecution.py`
- zero-knowledge mechanism: `zero_knowledge.py`

This keeps downstream components like compliance and disclosure agnostic to how
correctness was established, while letting each workload-specific mechanism own
its own evidence format and addressing details.

## Reference

- [Architecture overview](https://www.notion.so/Architecture-overview-701a53391ac345e88a15eb2aae7f2ce3)
- [Workload transparency system architecture](https://www.notion.so/Workload-transparency-system-architecture-31e399515d9e808ea310cf831ed25e57)
- [Physical transparency system architecture](https://www.notion.so/Physical-transparency-system-architecture-31a399515d9e819eb2a1d225fcd056b5)
