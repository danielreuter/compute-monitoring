# Vilnius — Confidential Compute Monitoring Prototype

## What this is

A single-process, deterministic simulation of a prover/verifier monitoring system for confidential compute. No transport, no async, no framework — just an event log, a runtime loop, and participants that read and write events.

## Core architecture

There is one shared append-only `EventLog`. A `Runtime` drives a deterministic dispatch loop. Participants implement `on_event` and `on_tick` to read from and write to the log. That's the whole thing.

### Per-protocol prover/verifier pairs

Each protocol defines its own prover and verifier as co-located participants in the same file:

- **Prover participants** hold internal state, expose methods for the outside world to push data in (e.g. `report_inference()`, `report_sanitization()`), and emit transcript events on each tick.
- **Verifier participants** consume transcript events and produce verification, compliance, and disclosure events.

There is no central `ProverRuntime` — each protocol owns its prover's behavior. Callers (tests, real infrastructure) write directly to the prover participants.

```
Real compute world              Prover participant          Monitoring system
─────────────────              ──────────────────          ─────────────────
inference completes   →    prover.report_inference()  →    InferenceClaimedEvent
workload starts       →    prover.report_workload_started() → WorkloadStartedEvent
sanitization runs     →    prover.report_sanitization()   → MemorySanitizationPerformedEvent
```

### Why transcript events exist

Transcript events are not natural byproducts of compute. They exist because the verification protocol requires them. In a world with no monitoring system, the prover just runs inference and tells nobody. The transcript is the prover's obligation under the protocol: "if you want to be verified as compliant, you must emit these claims."

This is why transcript events and prover participants live in the protocol modules (`protocols/transparency/correctness.py`, etc.) rather than in the runtime — they are defined by what verification needs, not by what the prover happens to do.

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
protocols/
    transparency/
        correctness.py                       CorrectnessProver, CorrectnessVerifier, reexecution
        utilization.py                       UtilizationProver, utilization verifiers
        remote_attestation.py                Attestation events, RemoteAttestationVerifier
    compliance.py                            ComplianceVerifier
    disclosure.py                            DisclosurePublisher
examples/
    simple_inference.py                      End-to-end demo
tests/
    test_*.py                                unittest-based tests
ccm.py                                      Thin façade, render_summary() debug helper
```

## How to run

```bash
# Run the example
python3.12 -m examples.simple_inference

# Run tests
python3.12 -m unittest discover -s tests
```
