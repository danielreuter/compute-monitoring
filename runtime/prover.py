"""
Prover-side runtime participant with internal subsystem adapters.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from event_log import Event, Principal, TRANSCRIPT_READERS, VERIFICATION_READERS

from runtime.base import Participant as RuntimeParticipant
from runtime.engine import Runtime


# --- Adapter interfaces ---


class ProverSchedulerAdapter(Protocol):
    def start_workload(self, workload_id: str, node_id: str) -> list[Event]: ...
    def stop_workload(self, workload_id: str, node_id: str) -> list[Event]: ...


@dataclass(frozen=True)
class InferenceRunResult:
    output_bytes: bytes
    output_digest: str
    artifact_ref: CorrectnessArtifactRef


class ProverInferenceAdapter(Protocol):
    def run_inference(self, request_id: str, model_id: str, input_bytes: bytes) -> InferenceRunResult: ...
    def stop_engine(self) -> None: ...


class ProverControlAdapter(Protocol):
    def handle_command(self, command: str, payload: dict[str, object]) -> str: ...


class CorrectnessArtifactStore(Protocol):
    def store(self, ref: CorrectnessArtifactRef, bundle: ReexecutionBundle) -> None: ...
    def get(self, artifact_ref: CorrectnessArtifactRef) -> ReexecutionBundle | None: ...


# --- Forward-import types from correctness module ---
# These are re-imported here to avoid circular imports; the canonical definitions
# live in protocols.transparency.correctness.

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
)


# --- ProverRuntime ---


@dataclass
class ProverRuntime:
    principal: Principal = field(default=Principal.PROVER, init=False)
    scheduler: ProverSchedulerAdapter
    inference: ProverInferenceAdapter
    control: ProverControlAdapter
    artifacts: CorrectnessArtifactStore

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        if isinstance(event, CorrectnessCheckRequestedEvent):
            return self._handle_correctness_check(event, runtime)
        if isinstance(event, EngineStopRequestedEvent):
            return self._handle_engine_stop(event, runtime)
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        return []

    def _handle_correctness_check(
        self, event: CorrectnessCheckRequestedEvent, runtime: Runtime
    ) -> list[Event]:
        bundle = self.artifacts.get(event.artifact_ref)
        if bundle is None:
            return []
        return [
            CorrectnessArtifactPublishedEvent(
                event_id=runtime.make_event_id("artifact-published"),
                timestamp=runtime.now,
                principal=Principal.PROVER,
                source="prover_runtime",
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
                principal=Principal.PROVER,
                source="prover_runtime",
                readers=VERIFICATION_READERS,
                session_id=event.session_id,
                succeeded=succeeded,
                details=details,
            )
        ]

    # --- Convenience for examples / tests ---

    def perform_inference(
        self, runtime: Runtime, request_id: str, model_id: str, input_bytes: bytes
    ) -> InferenceRunResult:
        """Run inference through the adapter and emit the claim event."""
        import hashlib

        result = self.inference.run_inference(request_id, model_id, input_bytes)
        bundle = ReexecutionBundle(
            model_id=model_id,
            input_bytes=input_bytes,
            output_digest=result.output_digest,
            engine_digest="",
            metadata={},
        )
        self.artifacts.store(result.artifact_ref, bundle)
        input_digest = hashlib.sha256(input_bytes).hexdigest()[:16]
        claim = InferenceClaimedEvent(
            event_id=runtime.make_event_id("inference-claimed"),
            timestamp=runtime.now,
            principal=Principal.PROVER,
            source="prover_runtime",
            readers=TRANSCRIPT_READERS,
            request_id=request_id,
            model_id=model_id,
            input_digest=input_digest,
            output_digest=result.output_digest,
            artifact_ref=result.artifact_ref,
        )
        runtime.emit(claim)
        return result
