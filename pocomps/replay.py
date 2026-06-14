"""Full-replay PoComp prototype.

Core invariant:
    The observed measurement transcript is exactly the transcript produced by a
    committed predictor running with bounded advice through a deterministic
    simulator and instrumentation layer.

This module intentionally lives next to the older task-based prototype without
replacing it.
"""

from __future__ import annotations

from dataclasses import dataclass
import time
from typing import Any, Callable, Iterable, TypeVar

Hash = int
Advice = bytes
Site = str
Metadata = tuple[tuple[str, Any], ...]
T = TypeVar("T")


@dataclass
class Baseline:
    """Prior commitment to code, data, models, and predictor artifacts."""

    committed_hashes: set[Hash]

    def contains(self, artifact_hash: Hash) -> bool:
        return artifact_hash in self.committed_hashes


@dataclass(frozen=True)
class ObjectRef:
    """Opaque simulator handle for the object whose custody is tracked."""

    id: str


@dataclass(frozen=True)
class Object:
    """Committed payload being moved or opened."""

    ref: ObjectRef
    payload: Any
    commitment: str
    size: int
    metadata: Metadata = ()


@dataclass(frozen=True)
class Transfer:
    """The only simulator action in this prototype."""

    object_ref: ObjectRef
    src: Site
    dst: Site
    size: int
    metadata: Metadata = ()


@dataclass
class Topology:
    """Public rules for legal movement and origination."""

    sites: set[Site]
    links: set[tuple[Site, Site]]
    allowed_origins: set[Site]


@dataclass(frozen=True)
class Measurement:
    """Instrumentation observation of an accepted transfer."""

    hook_id: str
    ordinal: int
    object_ref: ObjectRef
    src: Site
    dst: Site
    size: int
    object_commitment: str | None = None
    metadata: Metadata = ()


@dataclass
class PolicyParams:
    predictor_hash: Hash
    advice_budget: int
    compute_budget: int


@dataclass
class RunResult:
    measurements: tuple[Measurement, ...]
    compute_cost: int
    advice_cost: int


Predictor = Callable[[Advice, Topology], Iterable[Transfer]]


class Simulator:
    """Deterministic topology-aware custody machine."""

    def __init__(self, topology: Topology) -> None:
        self.topology = topology
        self.custody: dict[ObjectRef, set[Site]] = {}

    def step(self, transfer: Transfer) -> Transfer:
        assert isinstance(transfer, Transfer), "INV-PREDICTOR-OUTPUT-TYPE"
        assert transfer.src in self.topology.sites, "INV-TOPOLOGY"
        assert transfer.dst in self.topology.sites, "INV-TOPOLOGY"
        assert (transfer.src, transfer.dst) in self.topology.links, "INV-TOPOLOGY"
        assert transfer.size >= 0, "INV-TRANSFER-SIZE"

        sites_with_object = self.custody.get(transfer.object_ref, set())
        has_custody = transfer.src in sites_with_object
        may_originate = transfer.src in self.topology.allowed_origins
        assert has_custody or may_originate, "INV-CUSTODY"

        self.custody.setdefault(transfer.object_ref, set()).add(transfer.dst)
        if has_custody:
            self.custody[transfer.object_ref].add(transfer.src)
        return transfer


class Instrumentation:
    """Deterministic observation layer attached to the simulator."""

    def __init__(self) -> None:
        self.next_ordinal = 0

    def observe(
        self,
        accepted_transfer: Transfer,
        _simulator: Simulator,
    ) -> tuple[Measurement, ...]:
        measurement = Measurement(
            hook_id="transfer",
            ordinal=self.next_ordinal,
            object_ref=accepted_transfer.object_ref,
            src=accepted_transfer.src,
            dst=accepted_transfer.dst,
            size=accepted_transfer.size,
            object_commitment=metadata_value(
                accepted_transfer.metadata,
                "object_commitment",
            ),
            metadata=accepted_transfer.metadata,
        )
        self.next_ordinal += 1
        return (measurement,)


def metadata_value(metadata: Metadata, key: str) -> Any | None:
    for item_key, item_value in metadata:
        if item_key == key:
            return item_value
    return None


def replay_transfers(
    transfers: Iterable[Transfer],
    topology: Topology,
) -> tuple[Measurement, ...]:
    simulator = Simulator(topology)
    instrumentation = Instrumentation()
    measurements: list[Measurement] = []

    for transfer in transfers:
        accepted_transfer = simulator.step(transfer)
        measurements.extend(
            instrumentation.observe(accepted_transfer, simulator),
        )

    return tuple(measurements)


def audit_epoch(
    observed_measurements: tuple[Measurement, ...],
    baseline: Baseline,
    topology: Topology,
    params: PolicyParams,
    advice: Advice,
    predictor: Predictor,
) -> RunResult:
    assert baseline.contains(params.predictor_hash), "INV-PREDICTOR-COMMITMENT"
    assert len(advice) <= params.advice_budget, "INV-ADVICE-BUDGET"

    started_at = time.perf_counter()
    transfers = tuple(predictor(advice, topology))
    assert all(isinstance(transfer, Transfer) for transfer in transfers), (
        "INV-PREDICTOR-OUTPUT-TYPE"
    )
    replay_measurements = replay_transfers(transfers, topology)
    compute_cost = round(time.perf_counter() - started_at)

    assert compute_cost >= 0, "INV-RUN-COST"
    assert compute_cost <= params.compute_budget, "INV-COMPUTE-BUDGET"
    assert replay_measurements == observed_measurements, "INV-REPLAY-CORRECTNESS"

    return RunResult(
        measurements=replay_measurements,
        compute_cost=compute_cost,
        advice_cost=len(advice),
    )
