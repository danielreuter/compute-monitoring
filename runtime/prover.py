"""
Prover-side runtime participant with internal subsystem adapters.

The prover is an instrumented runtime that wraps real compute infrastructure.
It does not *cause* inference or workload scheduling — those happen independently.
The prover's job is to observe what happened (via adapters) and emit the transcript
events that the monitoring protocol requires.

Adapters are "what happened?" feeds, not "do the thing" commands. On each tick,
the prover drains pending records from its adapters and emits the corresponding
protocol-required claim events. The adapters are the boundary between the real
compute world and the monitoring system's view of it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from event_log import Event, Role, TRANSCRIPT_READERS, VERIFICATION_READERS
from runtime.engine import Runtime


# --- Records returned by adapters ---


@dataclass(frozen=True)
class InferenceRecord:
    request_id: str
    model_id: str
    input_digest: str
    output_digest: str
    artifact_ref: CorrectnessArtifactRef
    bundle: ReexecutionBundle


@dataclass(frozen=True)
class SchedulerRecord:
    workload_id: str
    machine_id: str
    started: bool  # True = started, False = terminated


@dataclass(frozen=True)
class SanitizationRecord:
    machine_id: str
    epoch: int
    merkle_root: str
    spot_check_passed: bool


# --- Adapter interfaces ---


class ProverInferenceAdapter(Protocol):
    """Reports what inference happened since last drain."""
    def pending_claims(self) -> list[InferenceRecord]: ...
    def get_bundle(self, artifact_ref: CorrectnessArtifactRef) -> ReexecutionBundle | None: ...
    def stop_engine(self) -> None: ...


class ProverSchedulerAdapter(Protocol):
    """Reports workload lifecycle changes since last drain."""
    def pending_changes(self) -> list[SchedulerRecord]: ...


class ProverSanitizationAdapter(Protocol):
    """Reports sanitization attestations since last drain."""
    def pending_attestations(self) -> list[SanitizationRecord]: ...


class ProverControlAdapter(Protocol):
    def handle_command(self, command: str, payload: dict[str, object]) -> str: ...


# --- Forward-import types from protocol modules ---

from protocols.transparency.correctness import (
    CorrectnessArtifactPublishedEvent,
    CorrectnessArtifactRef,
    CorrectnessCheckRequestedEvent,
    InferenceClaimedEvent,
    ReexecutionBundle,
)
from protocols.transparency.utilization import (
    EngineStopAcknowledgedEvent,
    EngineStopRequestedEvent,
    MemorySanitizationPerformedEvent,
    WorkloadStartedEvent,
    WorkloadTerminatedEvent,
)


# --- ProverRuntime ---


@dataclass
class ProverRuntime:
    writer: Role = field(default=Role.PROVER, init=False)
    inference: ProverInferenceAdapter
    scheduler: ProverSchedulerAdapter
    sanitization: ProverSanitizationAdapter
    control: ProverControlAdapter

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        if isinstance(event, CorrectnessCheckRequestedEvent):
            return self._handle_correctness_check(event, runtime)
        if isinstance(event, EngineStopRequestedEvent):
            return self._handle_engine_stop(event, runtime)
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        events: list[Event] = []
        events.extend(self._drain_scheduler(runtime))
        events.extend(self._drain_inference(runtime))
        events.extend(self._drain_sanitization(runtime))
        return events

    # --- Drain adapters into transcript events ---

    def _drain_inference(self, runtime: Runtime) -> list[Event]:
        events: list[Event] = []
        for record in self.inference.pending_claims():
            events.append(
                InferenceClaimedEvent(
                    event_id=runtime.make_event_id("inference-claimed"),
                    timestamp=runtime.now,
                    writer=Role.PROVER,
                    readers=TRANSCRIPT_READERS,
                    request_id=record.request_id,
                    model_id=record.model_id,
                    input_digest=record.input_digest,
                    output_digest=record.output_digest,
                    artifact_ref=record.artifact_ref,
                )
            )
        return events

    def _drain_scheduler(self, runtime: Runtime) -> list[Event]:
        events: list[Event] = []
        for record in self.scheduler.pending_changes():
            if record.started:
                events.append(
                    WorkloadStartedEvent(
                        event_id=runtime.make_event_id("workload-started"),
                        timestamp=runtime.now,
                        writer=Role.PROVER,
                        readers=TRANSCRIPT_READERS,
                        workload_id=record.workload_id,
                        machine_id=record.machine_id,
                    )
                )
            else:
                events.append(
                    WorkloadTerminatedEvent(
                        event_id=runtime.make_event_id("workload-terminated"),
                        timestamp=runtime.now,
                        writer=Role.PROVER,
                        readers=TRANSCRIPT_READERS,
                        workload_id=record.workload_id,
                        machine_id=record.machine_id,
                    )
                )
        return events

    def _drain_sanitization(self, runtime: Runtime) -> list[Event]:
        events: list[Event] = []
        for record in self.sanitization.pending_attestations():
            events.append(
                MemorySanitizationPerformedEvent(
                    event_id=runtime.make_event_id("sanitization"),
                    timestamp=runtime.now,
                    writer=Role.PROVER,
                    readers=TRANSCRIPT_READERS,
                    machine_id=record.machine_id,
                    epoch=record.epoch,
                    merkle_root=record.merkle_root,
                    spot_check_passed=record.spot_check_passed,
                )
            )
        return events

    # --- Respond to verifier requests ---

    def _handle_correctness_check(
        self, event: CorrectnessCheckRequestedEvent, runtime: Runtime
    ) -> list[Event]:
        bundle = self.inference.get_bundle(event.artifact_ref)
        if bundle is None:
            return []
        return [
            CorrectnessArtifactPublishedEvent(
                event_id=runtime.make_event_id("artifact-published"),
                timestamp=runtime.now,
                writer=Role.PROVER,
                readers=VERIFICATION_READERS,
                session_id=event.session_id,
                in_reply_to=event.event_id,
                artifact_ref=event.artifact_ref,
                bundle=bundle,
            )
        ]

    def _handle_engine_stop(
        self, event: EngineStopRequestedEvent, runtime: Runtime
    ) -> list[Event]:
        try:
            self.inference.stop_engine()
            succeeded = True
            details = "engine stopped"
        except Exception as exc:
            succeeded = False
            details = str(exc)
        return [
            EngineStopAcknowledgedEvent(
                event_id=runtime.make_event_id("engine-stop-ack"),
                timestamp=runtime.now,
                writer=Role.PROVER,
                readers=VERIFICATION_READERS,
                session_id=event.session_id,
                succeeded=succeeded,
                details=details,
            )
        ]
