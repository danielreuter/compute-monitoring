# Vilnius — Confidential Compute Monitoring Prototype

## What this is

A single-process, deterministic simulation of a prover/verifier monitoring system for confidential compute. No transport, no async, no framework — just an event log, a runtime loop, and participants that read and write events.

## Core architecture

There is one shared append-only `EventLog`. A `Runtime` drives a deterministic dispatch loop. Participants implement `on_event` and `on_tick` to read from and write to the log. That's the whole thing.

### The two principals

- **Prover**: an instrumented runtime wrapping real compute infrastructure. It observes what the underlying system did and emits transcript events that the monitoring protocol requires.
- **Verifier(s)**: protocol participants that consume transcript events and produce verification, compliance, and disclosure events.

### Key design principle: adapters are feeds, not commands

The prover does not *cause* inference or workload scheduling. Those happen independently, outside the monitoring system. The prover's job is to observe what happened and report it.

Adapters are the boundary between "the real world" and "the monitoring system's view of it." They answer "what happened since last time?" — not "do this thing."

```
Real compute world          Adapter boundary         Monitoring system
─────────────────          ────────────────         ─────────────────
inference completes   →    pending_claims()    →    InferenceClaimedEvent
workload starts       →    pending_changes()   →    WorkloadStartedEvent
sanitization runs     →    pending_attestations() → MemorySanitizationPerformedEvent
```

On each tick, `ProverRuntime.on_tick` drains all adapters and emits the corresponding protocol-required transcript events. The prover never reaches outside the participant contract to emit events — everything flows through `on_tick` (for reporting) and `on_event` (for responding to verifier requests).

### Why transcript events exist

Transcript events are not natural byproducts of compute. They exist because the verification protocol requires them. In a world with no monitoring system, the prover just runs inference and tells nobody. The transcript is the prover's obligation under the protocol: "if you want to be verified as compliant, you must emit these claims."

This is why transcript events live in the protocol modules (`protocols/transparency/correctness.py`, etc.) rather than with the prover — they are defined by what verification needs, not by what the prover happens to do.

### Runtime semantics

- `emit(event)`: append to log, enqueue for delivery
- `dispatch_until_quiescent()`: FIFO delivery to all participants in registration order; participants may emit more events; repeat until queue is empty
- `tick(delta)`: advance clock, call `on_tick` on each participant, then dispatch until quiescent
- Participants see their own events and must self-filter if needed
- No async, no concurrency, no deduplication

### Event views and readers

- **Transcript** (`EventView.TRANSCRIPT`): prover-emitted claims about what happened — inference, workloads, machines, sanitization, attestation, network observations
- **Verification** (`EventView.VERIFICATION`): verifier-originated challenges, responses, and evaluations
- **Disclosure** (`EventView.DISCLOSURE`): public compliance results

`readers` is an information-flow annotation, not a runtime delivery filter. All participants see all events at runtime.

## File layout

```
event_log.py                                 Event, EventLog, Role, EventView
runtime/
    base.py                                  Participant protocol
    engine.py                                Runtime driver
    prover.py                                ProverRuntime + adapter interfaces
protocols/
    transparency/
        correctness.py                       InferenceClaimedEvent, CorrectnessVerifier, reexecution
        utilization.py                       Machine/workload/sanitization events, utilization verifiers
        remote_attestation.py                Attestation events, RemoteAttestationVerifier
    compliance.py                            ComplianceVerifier
    disclosure.py                            DisclosurePublisher
examples/
    simple_inference.py                      End-to-end demo
tests/
    _toy_adapters.py                         Shared test adapter implementations
    test_*.py                                unittest-based tests
ccm.py                                      Thin façade, render_summary() debug helper
```

## How to run

```bash
# Run the example
.venv/bin/python -m examples.simple_inference

# Run tests
.venv/bin/python -m unittest discover -s tests
```
