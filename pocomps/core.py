"""PoComp prototype centered on measurement metadata and payload prediction.

The auditor must be able to see exactly how much entropy and compute it costs
to predict the epoch transcript metadata, and then to predict sampled payloads.

Core invariant:
    Virtually all of the epoch's measurements can be explained by the committed
    metadata and payload predictors using bounded advice and bounded compute.

Here, committed predictors are represented by hashes in the policy and
baseline. The prototype runs normal Python callables supplied by the example as
trusted stand-ins for those committed artifacts.

Security invariants:

INV-POLICY-PARAMS:
    The per-measurement sampling rate is in [0, 1].

INV-OBJECT-OPENING:
    Opened payload objects match the requested hash.

INV-PREDICTOR-COMMITMENT:
    Predictor hashes are committed in the baseline.

INV-PREDICTOR-OUTPUT-TYPE:
    Predictor outputs have the wrapper-expected Python shape.

INV-METADATA-CORRECTNESS:
    Predicted transcript metadata exactly matches observed metadata.

INV-METADATA-ENTROPY:
    Metadata advice consumes at most the epoch metadata-entropy budget.

INV-METADATA-COMPUTE:
    Metadata prediction consumes at most the epoch metadata-compute budget.

INV-PAYLOAD-ENTROPY:
    Sampled payload advice consumes at most the per-payload entropy budget.

INV-PAYLOAD-COMPUTE:
    Sampled payload prediction consumes at most the per-payload compute budget.

INV-REPLAY-CORRECTNESS:
    Sampled payload prediction reproduces the recorded payload commitment.

INV-ADVICE-SHAPE:
    Per-payload advice tuples match the measurement count.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any, Callable, Generic, Sequence, TypeVar

Hash = int
Id = int
Advice = str
Object = Any
T = TypeVar("T")


@dataclass(frozen=True)
class Measurement:
    metadata: Any
    payload: Hash


@dataclass
class PolicyParams:
    metadata_predictor_hash: Hash
    payload_predictor_hash: Hash
    metadata_entropy_budget_per_epoch: int
    compute_budget_for_metadata: int
    entropy_budget_per_payload: int
    compute_budget_per_payload: int
    sample_rate_per_measurement: float


@dataclass
class Storage:
    """Content-addressed storage for hashable Python payload objects."""

    objects: dict[Hash, Object]

    def read(self, object_hash: Hash) -> Object:
        assert object_hash in self.objects, "INV-OBJECT-OPENING"
        payload_object = self.objects[object_hash]
        assert hash(payload_object) == object_hash, "INV-OBJECT-OPENING"
        return payload_object

    def read_many(self, object_hashes: Sequence[Hash]) -> tuple[Object, ...]:
        return tuple(self.read(object_hash) for object_hash in object_hashes)


@dataclass
class Baseline:
    """Prior commitment to predictor code, data, and models."""

    committed_hashes: set[Hash]

    def contains(self, object_hash: Hash) -> bool:
        return object_hash in self.committed_hashes


@dataclass
class PredictionResult(Generic[T]):
    value: T
    compute_cost: int = 0
    entropy_cost: int = 0


@dataclass
class AuditResult:
    """Epoch-level metadata result plus sampled payload prediction results."""

    metadata_prediction: PredictionResult[tuple[Any, ...]]
    sampled_measurement_ids: tuple[Id, ...]
    payload_predictions: tuple[PredictionResult[Object], ...]


MeasurementMetadataPredictor = Callable[[Advice], tuple[Any, ...]]
MeasurementPayloadPredictor = Callable[[Id, Any, Advice, Advice], Object]


def execute(fn: Callable[[], T]) -> tuple[T, int]:
    started_at = time.perf_counter()
    value = fn()
    elapsed_seconds = time.perf_counter() - started_at
    return value, round(elapsed_seconds)


def predict_metadata(
    baseline: Baseline,
    params: PolicyParams,
    metadata_advice: Advice,
    predictor: MeasurementMetadataPredictor,
) -> PredictionResult[tuple[Any, ...]]:
    assert baseline.contains(params.metadata_predictor_hash), (
        "INV-PREDICTOR-COMMITMENT"
    )
    predicted_metadata, compute_cost = execute(lambda: predictor(metadata_advice))

    assert isinstance(predicted_metadata, tuple), "INV-PREDICTOR-OUTPUT-TYPE"

    return PredictionResult(
        value=predicted_metadata,
        compute_cost=compute_cost,
        entropy_cost=len(metadata_advice),
    )


def predict_payload(
    baseline: Baseline,
    params: PolicyParams,
    measurement_id: Id,
    metadata: Any,
    metadata_advice: Advice,
    payload_advice: Advice,
    predictor: MeasurementPayloadPredictor,
) -> PredictionResult[Object]:
    assert baseline.contains(params.payload_predictor_hash), (
        "INV-PREDICTOR-COMMITMENT"
    )

    predicted_payload, compute_cost = execute(
        lambda: predictor(
            measurement_id,
            metadata,
            metadata_advice,
            payload_advice,
        )
    )

    return PredictionResult(
        value=predicted_payload,
        compute_cost=compute_cost,
        entropy_cost=len(payload_advice),
    )


def sample_measurement_ids(
    measurement_count: int,
    sampling_prob: float,
    beacon: bytes,
) -> tuple[Id, ...]:
    rng = random.Random(beacon)
    sample: list[Id] = []
    for measurement_id in range(measurement_count):
        if rng.random() < sampling_prob:
            sample.append(measurement_id)
    return tuple(sample)


def audit_epoch(
    measurements: Sequence[Measurement],
    storage: Storage,
    baseline: Baseline,
    params: PolicyParams,
    beacon: bytes,
    metadata_advice: Advice,
    payload_advice: tuple[Advice, ...],
    predict_measurement_metadata: MeasurementMetadataPredictor,
    predict_measurement_payload: MeasurementPayloadPredictor,
) -> AuditResult:
    measurements = tuple(measurements)
    assert 0 <= params.sample_rate_per_measurement <= 1, "INV-POLICY-PARAMS"
    assert len(payload_advice) == len(measurements), "INV-ADVICE-SHAPE"

    metadata_result = predict_metadata(
        baseline,
        params,
        metadata_advice,
        predict_measurement_metadata,
    )

    assert metadata_result.entropy_cost <= params.metadata_entropy_budget_per_epoch, (
        "INV-METADATA-ENTROPY"
    )
    assert metadata_result.compute_cost <= params.compute_budget_for_metadata, (
        "INV-METADATA-COMPUTE"
    )
    observed_metadata = tuple(measurement.metadata for measurement in measurements)
    assert metadata_result.value == observed_metadata, "INV-METADATA-CORRECTNESS"

    for measurement in measurements:
        storage.read(measurement.payload)

    sampled_measurement_ids = sample_measurement_ids(
        len(measurements),
        params.sample_rate_per_measurement,
        beacon,
    )

    payload_predictions: list[PredictionResult[Object]] = []
    for measurement_id in sampled_measurement_ids:
        assert 0 <= measurement_id < len(measurements), "INV-MEASUREMENT-VALIDITY"
        measurement = measurements[measurement_id]
        payload_prediction = predict_payload(
            baseline,
            params,
            measurement_id,
            measurement.metadata,
            metadata_advice,
            payload_advice[measurement_id],
            predict_measurement_payload,
        )

        assert payload_prediction.entropy_cost <= params.entropy_budget_per_payload, (
            "INV-PAYLOAD-ENTROPY"
        )
        assert payload_prediction.compute_cost <= params.compute_budget_per_payload, (
            "INV-PAYLOAD-COMPUTE"
        )
        assert hash(payload_prediction.value) == measurement.payload, (
            "INV-REPLAY-CORRECTNESS"
        )

        payload_predictions.append(payload_prediction)

    return AuditResult(
        metadata_prediction=metadata_result,
        sampled_measurement_ids=sampled_measurement_ids,
        payload_predictions=tuple(payload_predictions),
    )
