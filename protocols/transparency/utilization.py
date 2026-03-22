"""
Utilization transparency: machine inventory, workloads, network, memory sanitization,
and interactive control events.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from event_log import (
    Event,
    EventView,
    Side,
    TRANSCRIPT_READERS,
    VERIFICATION_READERS,
)
from runtime.base import Role
from runtime.engine import Runtime


# --- Transcript events ---


@dataclass(frozen=True, kw_only=True)
class MachineAddedEvent(Event):
    machine_id: str
    machine_kind: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


@dataclass(frozen=True, kw_only=True)
class MachineRemovedEvent(Event):
    machine_id: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


@dataclass(frozen=True, kw_only=True)
class WorkloadStartedEvent(Event):
    workload_id: str
    machine_id: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


@dataclass(frozen=True, kw_only=True)
class WorkloadTerminatedEvent(Event):
    workload_id: str
    machine_id: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


@dataclass(frozen=True, kw_only=True)
class NetworkObservationEvent(Event):
    observation_id: str
    data_digest: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


@dataclass(frozen=True, kw_only=True)
class MemorySanitizationPerformedEvent(Event):
    machine_id: str
    epoch: int
    merkle_root: str
    spot_check_passed: bool

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


# --- Interactive control events ---


@dataclass(frozen=True, kw_only=True)
class EngineStopRequestedEvent(Event):
    session_id: str
    reason: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class EngineStopAcknowledgedEvent(Event):
    session_id: str
    succeeded: bool
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


# --- Evaluation events ---


@dataclass(frozen=True, kw_only=True)
class ScheduleCoverageEvaluatedEvent(Event):
    passed: bool
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class SanitizationFrequencyEvaluatedEvent(Event):
    passed: bool
    gap_count: int
    max_gap_seconds: float
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class NetworkUtilizationEvaluatedEvent(Event):
    passed: bool
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class CovertCapacityEstimatedEvent(Event):
    io_capacity_bits: float
    persistence_capacity_bytes: float
    sustained_memory_bytes: float
    compute_capacity_flops: float

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


# --- Prover role ---


@dataclass
class UtilizationProver:
    writer: Side = field(default=Side.PROVER, init=False)

    _pending_workloads: list[tuple[str, str, bool]] = field(
        default_factory=list, init=False, repr=False
    )
    _pending_sanitizations: list[tuple[str, int, str, bool]] = field(
        default_factory=list, init=False, repr=False
    )

    def report_workload_started(self, workload_id: str, machine_id: str) -> None:
        self._pending_workloads.append((workload_id, machine_id, True))

    def report_workload_terminated(self, workload_id: str, machine_id: str) -> None:
        self._pending_workloads.append((workload_id, machine_id, False))

    def report_sanitization(
        self,
        machine_id: str,
        epoch: int,
        merkle_root: str,
        spot_check_passed: bool = True,
    ) -> None:
        self._pending_sanitizations.append(
            (machine_id, epoch, merkle_root, spot_check_passed)
        )

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        if isinstance(event, EngineStopRequestedEvent):
            return [
                EngineStopAcknowledgedEvent(
                    event_id=runtime.make_event_id("engine-stop-ack"),
                    timestamp=runtime.now,
                    writer=Side.PROVER,
                    readers=VERIFICATION_READERS,
                    session_id=event.session_id,
                    succeeded=True,
                    details="engine stopped",
                )
            ]
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        events: list[Event] = []

        for workload_id, machine_id, started in self._pending_workloads:
            if started:
                events.append(
                    WorkloadStartedEvent(
                        event_id=runtime.make_event_id("workload-started"),
                        timestamp=runtime.now,
                        writer=Side.PROVER,
                        readers=TRANSCRIPT_READERS,
                        workload_id=workload_id,
                        machine_id=machine_id,
                    )
                )
            else:
                events.append(
                    WorkloadTerminatedEvent(
                        event_id=runtime.make_event_id("workload-terminated"),
                        timestamp=runtime.now,
                        writer=Side.PROVER,
                        readers=TRANSCRIPT_READERS,
                        workload_id=workload_id,
                        machine_id=machine_id,
                    )
                )
        self._pending_workloads.clear()

        for machine_id, epoch, merkle_root, spot_check_passed in self._pending_sanitizations:
            events.append(
                MemorySanitizationPerformedEvent(
                    event_id=runtime.make_event_id("sanitization"),
                    timestamp=runtime.now,
                    writer=Side.PROVER,
                    readers=TRANSCRIPT_READERS,
                    machine_id=machine_id,
                    epoch=epoch,
                    merkle_root=merkle_root,
                    spot_check_passed=spot_check_passed,
                )
            )
        self._pending_sanitizations.clear()

        return events


# --- Verifier roles ---


@dataclass
class ScheduleCoverageVerifier:
    writer: Side = field(default=Side.VERIFIER, init=False)

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        started = runtime.log.of_type(WorkloadStartedEvent)
        terminated = runtime.log.of_type(WorkloadTerminatedEvent)
        return [
            ScheduleCoverageEvaluatedEvent(
                event_id=runtime.make_event_id("schedule-coverage"),
                timestamp=runtime.now,
                writer=Side.VERIFIER,
                readers=VERIFICATION_READERS,
                passed=True,
                details=f"{len(started)} started, {len(terminated)} terminated",
            )
        ]


@dataclass
class SanitizationFrequencyVerifier:
    writer: Side = field(default=Side.VERIFIER, init=False)
    max_gap_seconds: float = 5.0

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        attestations = sorted(
            runtime.log.of_type(MemorySanitizationPerformedEvent),
            key=lambda e: e.timestamp,
        )
        gaps = [
            attestations[i].timestamp - attestations[i - 1].timestamp
            for i in range(1, len(attestations))
            if attestations[i].timestamp - attestations[i - 1].timestamp > self.max_gap_seconds
        ]
        return [
            SanitizationFrequencyEvaluatedEvent(
                event_id=runtime.make_event_id("sanitization-frequency"),
                timestamp=runtime.now,
                writer=Side.VERIFIER,
                readers=VERIFICATION_READERS,
                passed=len(gaps) == 0,
                gap_count=len(gaps),
                max_gap_seconds=self.max_gap_seconds,
                details=f"{len(attestations)} attestations, {len(gaps)} gaps > {self.max_gap_seconds}s",
            )
        ]


@dataclass
class NetworkUtilizationVerifier:
    writer: Side = field(default=Side.VERIFIER, init=False)

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        observations = runtime.log.of_type(NetworkObservationEvent)
        return [
            NetworkUtilizationEvaluatedEvent(
                event_id=runtime.make_event_id("network-utilization"),
                timestamp=runtime.now,
                writer=Side.VERIFIER,
                readers=VERIFICATION_READERS,
                passed=True,
                details=f"{len(observations)} network observations",
            )
        ]


@dataclass
class CovertCapacityEstimator:
    writer: Side = field(default=Side.VERIFIER, init=False)
    sram_per_gpu_bytes: int = 0
    num_gpus: int = 0
    excess_capacity_bytes: int = 0

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        persistence = float(self.sram_per_gpu_bytes * self.num_gpus)
        sustained = persistence + float(self.excess_capacity_bytes)
        return [
            CovertCapacityEstimatedEvent(
                event_id=runtime.make_event_id("covert-capacity"),
                timestamp=runtime.now,
                writer=Side.VERIFIER,
                readers=VERIFICATION_READERS,
                io_capacity_bits=0.0,
                persistence_capacity_bytes=persistence,
                sustained_memory_bytes=sustained,
                compute_capacity_flops=0.0,
            )
        ]
