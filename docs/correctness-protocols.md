# Correctness Protocol Structure

The correctness family now separates **shared protocol semantics** from
**mechanism-specific evidence exchange**.

## Design goals

- keep downstream consumers agnostic to how correctness was established
- make reexecution and zero-knowledge flows explicit instead of hiding them
  behind one generic strategy interface
- leave workload-specific addressability outside the shared runtime and inside
  the relevant protocol implementation
- stay deterministic and single-process

## Shared surface

These types are shared across all correctness mechanisms:

- `InferenceClaimedEvent`: transcript claim that an inference ran and was
  committed to
- `CorrectnessCheckRequestedEvent`: verifier sampled a claim and opened a
  challenge session
- `CorrectnessCheckTimedOutEvent`: challenge session expired without evidence
- `CorrectnessEvaluatedEvent`: final correctness result consumed by compliance
  and disclosure
- `CorrectnessCommitmentRef`: opaque commitment handle plus commitment scheme
- `WorkloadAddress`: opaque workload-specific locator for the committed item

This is the only correctness interface downstream protocols need to care about.

## Mechanisms

### `reexecution.py`

Used when the verifier checks correctness by rerunning sampled work.

- prover emits `InferenceClaimedEvent`
- verifier samples claims and emits `CorrectnessCheckRequestedEvent`
- prover returns `ReexecutionEvidencePublishedEvent`
- verifier recomputes and emits `CorrectnessEvaluatedEvent`

### `zero_knowledge.py`

Used when the prover answers the challenge with a proof.

- prover emits `InferenceClaimedEvent`
- verifier samples claims and emits `CorrectnessCheckRequestedEvent`
- prover returns `ZeroKnowledgeProofSubmittedEvent`
- verifier validates proof and emits `CorrectnessEvaluatedEvent`

## Addressability

Addressability is intentionally modeled as an opaque `WorkloadAddress`.

That means the shared runtime only knows there is some stable locator for the
thing that was committed to. How that locator is constructed — request ID,
sequence number, shard/index pair, Merkle path selector, token span, etc. — is
owned by the workload-specific protocol.

## Why not a shared `prove()` / `verify()` strategy API?

Because the control flow is not the same:

- reexecution asks for artifacts and recomputation inputs
- zero-knowledge asks for a proof object and verifier metadata

They share **security intent**, not **evidence shape**. The clean boundary is
therefore shared events plus separate files, not one polymorphic proof strategy.
