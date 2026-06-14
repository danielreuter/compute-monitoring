"""PoComp prototype.

Core invariant:
    Virtually all of the epoch's measurements can be explained by the committed
    predictor using bounded advice and bounded compute.

Here, the committed predictor is represented by a hash in the policy and
baseline. The prototype runs normal Python callables supplied by the example as
trusted stand-ins for those committed artifacts.

Security invariants:

INV-POLICY-PARAMS:
    The per-output-byte sampling rate is in [0, 1].

INV-EVENT-SIZE:
    Recorded blob sizes are nonnegative. We assume event sizes are derived
    from the hashed blob preimage, so checking the hash suffices when a
    blob is opened.

INV-BLOB-OPENING:
    Opened blob objects match the requested hash.

INV-PREDICTOR-COMMITMENT:
    Predictor hashes are committed in the baseline.

INV-PREDICTOR-OUTPUT-TYPE:
    Predictor outputs have the wrapper-expected Python shape.

INV-OUTPUT-VALIDITY:
    Every task measurement id is a valid monitored measurement handle.

INV-OUTPUT-OWNERSHIP:
    No measurement id appears on the right side of more than one task.

INV-OUTPUT-COVERAGE:
    Every monitored output measurement is covered by exactly one task.

INV-INPUT-VALIDITY:
    Every task input hash is baseline-committed; sampled input hashes open.

INV-TASK-LOCALITY:
    A task's measurement ids are emitted by one site.

INV-ENVIRONMENT-VALIDITY:
    Environment event blobs can be opened.

INV-RUN-COST:
    Predictor runs report nonnegative compute and entropy costs.

INV-EPOCH-ERROR-ENTROPY:
    Predictor runs consume at most the epoch error-entropy budget.

INV-TASK-COMPUTE:
    Task prediction consumes at most the task-prediction compute budget.

INV-REPLAY-COMPUTE:
    Sampled measurement prediction consumes at most the per-task compute budget.

INV-REPLAY-ENTROPY:
    Sampled measurement prediction consumes at most the per-task entropy budget.

INV-REPLAY-CORRECTNESS:
    Sampled measurement prediction reproduces the recorded output objects.
"""

from __future__ import annotations

import random
import time
from dataclasses import dataclass
from typing import Any, Callable, Generic, Sequence, TypeVar

Hash = int
Id = int
SiteId = int
Advice = str
Blob = Any
T = TypeVar("T")

EXTERNAL: SiteId = -1


@dataclass
class PolicyParams:
    task_predictor_hash: Hash
    measurement_predictor_hash: Hash
    compute_budget_for_tasks: int
    compute_budget_per_task: int
    error_entropy_budget_per_epoch: int
    entropy_budget_per_task: int
    sample_rate_per_output_byte: float


@dataclass
class Task:
    """Task that input blobs passed through a predictor explain measurement ids."""

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
    """Content-addressed storage for hashable Python objects."""

    blobs: dict[Hash, Blob]

    def read(self, blob_hash: Hash) -> Blob:
        assert blob_hash in self.blobs, "INV-BLOB-OPENING"
        blob = self.blobs[blob_hash]
        assert hash(blob) == blob_hash, "INV-BLOB-OPENING"
        return blob

    def read_many(self, blob_hashes: Sequence[Hash]) -> tuple[Blob, ...]:
        return tuple(self.read(blob_hash) for blob_hash in blob_hashes)


@dataclass
class Baseline:
    """Prior commitment to code, data, and models."""

    committed_hashes: set[Hash]

    def contains(self, blob_hash: Hash) -> bool:
        return blob_hash in self.committed_hashes


@dataclass
class RunResult(Generic[T]):
    value: T
    compute_cost: int = 0
    entropy_cost: int = 0


TaskPredictor = Callable[[NetworkEventLog, Advice], tuple[Task, ...]]
MeasurementPredictor = Callable[
    [Task, tuple[Blob, ...], Advice],
    tuple[Blob, ...],
]


def run_with_accounting(fn: Callable[[], T], advice: Advice) -> RunResult[T]:
    started_at = time.perf_counter()
    value = fn()
    elapsed_seconds = time.perf_counter() - started_at
    return RunResult(
        value=value,
        compute_cost=round(elapsed_seconds),
        entropy_cost=len(advice),
    )


def predict_tasks(
    event_log: NetworkEventLog,
    storage: Storage,
    baseline: Baseline,
    params: PolicyParams,
    advice: Advice,
    predictor: TaskPredictor,
) -> RunResult[tuple[Task, ...]]:
    assert baseline.contains(params.task_predictor_hash), "INV-PREDICTOR-COMMITMENT"
    result = run_with_accounting(lambda: predictor(event_log, advice), advice)

    tasks = result.value  # TODO: fix this type
    assert isinstance(tasks, tuple), "INV-PREDICTOR-OUTPUT-TYPE"
    assert all(isinstance(task, Task) for task in tasks), (
        "INV-PREDICTOR-OUTPUT-TYPE"
    )

    for event in event_log.events:
        assert event.blob_size >= 0, "INV-EVENT-SIZE"

    covered_measurement_ids: set[Id] = set()
    event_count = len(event_log.events)

    for task in tasks:
        for input_hash in task.input_hashes:
            assert baseline.contains(input_hash), "INV-INPUT-VALIDITY"

        assert task.measurement_ids, "INV-OUTPUT-VALIDITY"
        assert is_strictly_increasing(task.measurement_ids), "INV-OUTPUT-VALIDITY"

        output_senders: set[SiteId] = set()
        for measurement_id in task.measurement_ids:
            assert 0 <= measurement_id < event_count, "INV-OUTPUT-VALIDITY"
            event = event_log.events[measurement_id]
            assert is_monitored_output(event), "INV-OUTPUT-VALIDITY"
            assert measurement_id not in covered_measurement_ids, (
                "INV-OUTPUT-OWNERSHIP"
            )
            output_senders.add(event.sender)
            covered_measurement_ids.add(measurement_id)

        assert len(output_senders) == 1, "INV-TASK-LOCALITY"

    monitored_outputs = {
        event_id
        for event_id, event in enumerate(event_log.events)
        if is_monitored_output(event)
    }
    uncovered_outputs = monitored_outputs - covered_measurement_ids
    assert not uncovered_outputs, "INV-OUTPUT-COVERAGE"

    environment_events = {
        event_id
        for event_id, event in enumerate(event_log.events)
        if is_external_input(event)
    }
    for event_id in environment_events:
        storage.read(event_log.events[event_id].blob_hash)

    return RunResult(
        value=tasks,
        compute_cost=result.compute_cost,
        entropy_cost=result.entropy_cost,
    )


def predict_measurements(
    task: Task,
    event_log: NetworkEventLog,
    storage: Storage,
    baseline: Baseline,
    params: PolicyParams,
    advice: Advice,
    predictor: MeasurementPredictor,
) -> RunResult[tuple[Blob, ...]]:
    assert baseline.contains(params.measurement_predictor_hash), (
        "INV-PREDICTOR-COMMITMENT"
    )
    for input_hash in task.input_hashes:
        assert baseline.contains(input_hash), "INV-INPUT-VALIDITY"
        assert input_hash in storage.blobs, "INV-INPUT-VALIDITY"
    inputs = storage.read_many(task.input_hashes)
    result = run_with_accounting(lambda: predictor(task, inputs, advice), advice)

    measurements = result.value
    assert isinstance(measurements, tuple), "INV-PREDICTOR-OUTPUT-TYPE"

    assert len(measurements) == len(task.measurement_ids), (
        "INV-REPLAY-CORRECTNESS"
    )
    for measurement_id, measurement in zip(
        task.measurement_ids,
        measurements,
    ):
        event = event_log.events[measurement_id]
        assert hash(measurement) == event.blob_hash, "INV-REPLAY-CORRECTNESS"
        assert object_size(measurement) == event.blob_size, (
            "INV-REPLAY-CORRECTNESS"
        )

    return RunResult(
        value=measurements,
        compute_cost=result.compute_cost,
        entropy_cost=result.entropy_cost,
    )

def object_size(blob: Blob) -> int:
    try:
        return len(blob)
    except TypeError:
        return 1


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
    baseline: Baseline,
    params: PolicyParams,
    beacon: bytes,
    task_advice: Advice,
    measurement_advice: Advice,
    task_predictor: TaskPredictor,
    measurement_predictor: MeasurementPredictor,
) -> tuple[Task, ...]:

    # run task predictor
    task_result = predict_tasks(
        event_log,
        storage,
        baseline,
        params,
        task_advice,
        task_predictor,
    )

    tasks = task_result.value

    # verify budget compliance
    assert task_result.compute_cost >= 0, "INV-RUN-COST"
    assert task_result.entropy_cost >= 0, "INV-RUN-COST"
    assert task_result.compute_cost <= params.compute_budget_for_tasks, (
        "INV-TASK-COMPUTE"
    )

    # sample tasks to verify
    sample = sample_by_weight(
        tasks,
        lambda task: sum(
            event_log.events[i].blob_size for i in task.measurement_ids
        ),
        params.sample_rate_per_output_byte,
        beacon,
    )

    # verify sampled tasks
    run_results: list[RunResult[object]] = [task_result]
    for task in sample:

        # run measurement predictor
        measurement_result = predict_measurements(
            task,
            event_log,
            storage,
            baseline,
            params,
            measurement_advice,
            measurement_predictor,
        )

        # verify budget compliance
        assert measurement_result.compute_cost >= 0, "INV-RUN-COST"
        assert measurement_result.entropy_cost >= 0, "INV-RUN-COST"
        assert measurement_result.compute_cost <= params.compute_budget_per_task, (
            "INV-REPLAY-COMPUTE"
        )
        assert measurement_result.entropy_cost <= params.entropy_budget_per_task, (
            "INV-REPLAY-ENTROPY"
        )
        run_results.append(measurement_result)

    # verify per-epoch cumulative error entropy budget
    assert sum(run.entropy_cost for run in run_results) <= (
        params.error_entropy_budget_per_epoch
    ), "INV-EPOCH-ERROR-ENTROPY"
    return tasks
