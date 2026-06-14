"""PoComp prototype.

Core invariant:
    Virtually all of the epoch's measurements can be explained by the committed
    predictor using bounded advice and bounded compute.

Here, the committed predictor is the code and static blobs used to predict
claims and measurements. Predictor programs are fetched by protocol wrappers,
checked against the baseline commitment, and passed as bytes to interpret.

Security invariants:

INV-POLICY-PARAMS:
    The per-output-byte sampling rate is in [0, 1].

INV-EVENT-SIZE:
    Recorded blob sizes are nonnegative. We assume event sizes are derived
    from the hashed blob preimage, so checking the hash suffices when a
    blob is opened.

INV-BLOB-OPENING:
    Opened blob bytes match the requested hash.

INV-PREDICTOR-COMMITMENT:
    Predictor programs are opened from blobs committed in the baseline.

INV-PREDICTOR-OUTPUT-TYPE:
    Predictor outputs have the wrapper-expected Python shape.

INV-OUTPUT-VALIDITY:
    Every claim measurement id is a valid monitored measurement handle.

INV-OUTPUT-OWNERSHIP:
    No measurement id appears on the right side of more than one claim.

INV-OUTPUT-COVERAGE:
    Every monitored output measurement is claimed by exactly one claim.

INV-INPUT-VALIDITY:
    Every claim input hash is baseline-committed; sampled input hashes open to
    blob bytes.

INV-CLAIM-LOCALITY:
    A claim's measurement ids are emitted by one site.

INV-ENVIRONMENT-VALIDITY:
    Environment event blobs can be opened.

INV-RUN-COST:
    Interpret runs report nonnegative compute and entropy costs.

INV-EPOCH-ERROR-ENTROPY:
    Interpret runs consume at most the epoch error-entropy budget.

INV-CLAIM-COMPUTE:
    Claim prediction consumes at most the claim-prediction compute budget.

INV-REPLAY-COMPUTE:
    Sampled measurement prediction consumes at most the per-claim compute budget.

INV-REPLAY-ENTROPY:
    Sampled measurement prediction consumes at most the per-claim entropy budget.

INV-REPLAY-CORRECTNESS:
    Sampled measurement prediction reproduces the recorded output bytes.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Generic, Protocol, Sequence, TypeVar

Hash = int
Id = int
SiteId = int
Advice = str
T = TypeVar("T")

EXTERNAL: SiteId = -1


@dataclass
class PolicyParams:
    claim_predictor_hash: Hash
    measurement_predictor_hash: Hash
    compute_budget_for_claims: int
    compute_budget_per_claim: int
    error_entropy_budget_per_epoch: int
    entropy_budget_per_claim: int
    sample_rate_per_output_byte: float


@dataclass
class Claim:
    """Claim that input blobs passed through the interpreter (with additional advice) explain measurement ids."""

    input_hashes: tuple[Hash, ...]
    measurement_ids: tuple[Id, ...]


@dataclass
class NetworkEvent:
    sender: SiteId
    receiver: SiteId
    blob_hash: Hash
    blob_size: int


@dataclass
class NetworkEventLog:
    events: tuple[NetworkEvent, ...]


@dataclass
class Storage:
    """Content-addressed byte storage."""

    blobs: dict[Hash, bytes]

    def read(self, blob_hash: Hash) -> bytes:
        assert blob_hash in self.blobs, "INV-BLOB-OPENING"
        blob = self.blobs[blob_hash]
        assert hash(blob) == blob_hash, "INV-BLOB-OPENING"
        return blob

    def read_many(self, blob_hashes: Sequence[Hash]) -> tuple[bytes, ...]:
        return tuple(self.read(blob_hash) for blob_hash in blob_hashes)


class BaselineCommitment(Protocol):
    """Prior commitment to predictor code, data, and static state blobs."""

    def contains(self, blob_hash: Hash) -> bool: ...


@dataclass
class RunResult(Generic[T]):
    value: T
    compute_cost: int = 0
    entropy_cost: int = 0


def predict_claims(
    event_log: NetworkEventLog,
    storage: Storage,
    baseline: BaselineCommitment,
    params: PolicyParams,
    advice: Advice,
) -> RunResult[tuple[Claim, ...]]:
    assert baseline.contains(params.claim_predictor_hash), "INV-PREDICTOR-COMMITMENT"
    program = storage.read(params.claim_predictor_hash)
    result = interpret(program, event_log, advice)
    claims = result.value
    assert isinstance(claims, tuple), "INV-PREDICTOR-OUTPUT-TYPE"
    assert all(isinstance(claim, Claim) for claim in claims), (
        "INV-PREDICTOR-OUTPUT-TYPE"
    )

    for event in event_log.events:
        assert event.blob_size >= 0, "INV-EVENT-SIZE"

    claimed_measurement_ids: set[Id] = set()
    event_count = len(event_log.events)

    for claim in claims:
        for input_hash in claim.input_hashes:
            assert baseline.contains(input_hash), "INV-INPUT-VALIDITY"

        assert claim.measurement_ids, "INV-OUTPUT-VALIDITY"
        assert is_strictly_increasing(claim.measurement_ids), "INV-OUTPUT-VALIDITY"

        output_senders: set[SiteId] = set()
        for measurement_id in claim.measurement_ids:
            assert 0 <= measurement_id < event_count, "INV-OUTPUT-VALIDITY"
            event = event_log.events[measurement_id]
            assert is_monitored_output(event), "INV-OUTPUT-VALIDITY"
            assert measurement_id not in claimed_measurement_ids, (
                "INV-OUTPUT-OWNERSHIP"
            )
            output_senders.add(event.sender)
            claimed_measurement_ids.add(measurement_id)

        assert len(output_senders) == 1, "INV-CLAIM-LOCALITY"

    monitored_outputs = {
        event_id
        for event_id, event in enumerate(event_log.events)
        if is_monitored_output(event)
    }
    unclaimed_outputs = monitored_outputs - claimed_measurement_ids
    assert not unclaimed_outputs, "INV-OUTPUT-COVERAGE"

    environment_events = {
        event_id
        for event_id, event in enumerate(event_log.events)
        if is_external_input(event)
    }
    for event_id in environment_events:
        storage.read(event_log.events[event_id].blob_hash)

    return RunResult(
        value=claims,
        compute_cost=result.compute_cost,
        entropy_cost=result.entropy_cost,
    )


def predict_measurements(
    claim: Claim,
    event_log: NetworkEventLog,
    storage: Storage,
    baseline: BaselineCommitment,
    params: PolicyParams,
    advice: Advice,
) -> RunResult[tuple[bytes, ...]]:
    assert baseline.contains(params.measurement_predictor_hash), (
        "INV-PREDICTOR-COMMITMENT"
    )
    program = storage.read(params.measurement_predictor_hash)
    for input_hash in claim.input_hashes:
        assert baseline.contains(input_hash), "INV-INPUT-VALIDITY"
        assert input_hash in storage.blobs, "INV-INPUT-VALIDITY"
    inputs = storage.read_many(claim.input_hashes)
    result = interpret(program, claim, inputs, advice)
    measurements = result.value
    assert isinstance(measurements, tuple), "INV-PREDICTOR-OUTPUT-TYPE"
    assert all(isinstance(measurement, bytes) for measurement in measurements), (
        "INV-PREDICTOR-OUTPUT-TYPE"
    )

    assert len(measurements) == len(claim.measurement_ids), (
        "INV-REPLAY-CORRECTNESS"
    )
    for measurement_id, measurement in zip(
        claim.measurement_ids,
        measurements,
    ):
        event = event_log.events[measurement_id]
        assert hash(measurement) == event.blob_hash, "INV-REPLAY-CORRECTNESS"
        assert len(measurement) == event.blob_size, "INV-REPLAY-CORRECTNESS"

    return RunResult(
        value=measurements,
        compute_cost=result.compute_cost,
        entropy_cost=result.entropy_cost,
    )


def interpret(
    program: bytes,
    *args: object,
) -> RunResult[object]:
    """Public code executor that counts operations."""
    namespace: dict[str, object] = {}
    exec(compile(program, "<committed-predictor>", "exec"), namespace)
    main = namespace.get("main")
    compute_cost = namespace.get("COMPUTE_COST", 0)
    assert callable(main), "INV-PREDICTOR-COMMITMENT"
    assert isinstance(compute_cost, int), "INV-PREDICTOR-COMMITMENT"
    assert compute_cost >= 0, "INV-PREDICTOR-COMMITMENT"
    value = main(*args)
    advice = args[-1] if args and isinstance(args[-1], str) else ""
    return RunResult(
        value=value,
        compute_cost=compute_cost,
        entropy_cost=error_entropy_bits(advice),
    )


def error_entropy_bits(advice: Advice) -> int:
    return len(advice)  # TODO: replace with actual entropy calculation (this is wrong)


def is_strictly_increasing(values: Sequence[int]) -> bool:
    return all(left < right for left, right in zip(values, values[1:]))


def is_external_input(event: NetworkEvent) -> bool:
    return event.sender == EXTERNAL


def is_monitored_output(event: NetworkEvent) -> bool:
    return not is_external_input(event)


def sample_by_weight(
    items: Sequence[T],
    weight: Callable[[T], int | float],
    sampling_prob: float,
    beacon: bytes,
) -> tuple[T, ...]:
    rng = random.Random(beacon)
    sample: list[T] = []
    for item in items:
        if rng.random() < min(1, sampling_prob * weight(item)):
            sample.append(item)
    return tuple(sample)


def audit_epoch(
    event_log: NetworkEventLog,
    storage: Storage,
    baseline: BaselineCommitment,
    params: PolicyParams,
    beacon: bytes,
    claim_advice: Advice,
    measurement_advice: Advice,
) -> tuple[Claim, ...]:

    # run claim predictor
    claim_result = predict_claims(
        event_log,
        storage,
        baseline,
        params,
        claim_advice,
    )

    claims = claim_result.value

    # verify budget compliance
    assert claim_result.compute_cost >= 0, "INV-RUN-COST"
    assert claim_result.entropy_cost >= 0, "INV-RUN-COST"
    assert claim_result.compute_cost <= params.compute_budget_for_claims, (
        "INV-CLAIM-COMPUTE"
    )

    # sample claims to verify
    sample = sample_by_weight(
        claims,
        lambda claim: sum(
            event_log.events[i].blob_size for i in claim.measurement_ids
        ),
        params.sample_rate_per_output_byte,
        beacon,
    )

    # verify sampled claims
    run_results: list[RunResult[object]] = [claim_result]
    for claim in sample:

        # run measurement predictor
        measurement_result = predict_measurements(
            claim,
            event_log,
            storage,
            baseline,
            params,
            measurement_advice,
        )

        # verify budget compliance
        assert measurement_result.compute_cost >= 0, "INV-RUN-COST"
        assert measurement_result.entropy_cost >= 0, "INV-RUN-COST"
        assert measurement_result.compute_cost <= params.compute_budget_per_claim, (
            "INV-REPLAY-COMPUTE"
        )
        assert measurement_result.entropy_cost <= params.entropy_budget_per_claim, (
            "INV-REPLAY-ENTROPY"
        )
        run_results.append(measurement_result)

    # verify per-epoch cumulative error entropy budget
    assert sum(run.entropy_cost for run in run_results) <= (
        params.error_entropy_budget_per_epoch
    ), "INV-EPOCH-ERROR-ENTROPY"
    return claims
