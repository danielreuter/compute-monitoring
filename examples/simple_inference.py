"""
Simple inference example: demonstrates the full monitoring system in one process.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from event_log import Event, EventLog, Principal, TRANSCRIPT_READERS
from protocols.transparency.correctness import (
    CorrectnessArtifactRef,
    CorrectnessVerifier,
    ReexecutionBundle,
    ReexecutionStrategy,
)
from protocols.transparency.utilization import (
    CovertCapacityEstimator,
    MachineAddedEvent,
    MemorySanitizationPerformedEvent,
    NetworkUtilizationVerifier,
    SanitizationFrequencyVerifier,
    ScheduleCoverageVerifier,
    WorkloadStartedEvent,
)
from protocols.transparency.remote_attestation import (
    RemoteAttestationClaimedEvent,
    RemoteAttestationVerifier,
)
from protocols.compliance import ComplianceVerifier
from protocols.disclosure import DisclosurePublisher
from runtime.engine import Runtime
from runtime.prover import (
    CorrectnessArtifactStore,
    InferenceRunResult,
    ProverControlAdapter,
    ProverInferenceAdapter,
    ProverRuntime,
    ProverSchedulerAdapter,
)


# --- Toy adapter implementations ---


@dataclass
class ToyScheduler:
    def start_workload(self, workload_id: str, node_id: str) -> list[Event]:
        return []

    def stop_workload(self, workload_id: str, node_id: str) -> list[Event]:
        return []


@dataclass
class ToyInference:
    def run_inference(
        self, request_id: str, model_id: str, input_bytes: bytes
    ) -> InferenceRunResult:
        output = f"output-for-{request_id}".encode()
        digest = hashlib.sha256(output).hexdigest()[:16]
        return InferenceRunResult(
            output_bytes=output,
            output_digest=digest,
            artifact_ref=CorrectnessArtifactRef(artifact_id=f"artifact-{request_id}"),
        )

    def stop_engine(self) -> None:
        pass


@dataclass
class ToyControl:
    def handle_command(self, command: str, payload: dict[str, object]) -> str:
        return "ok"


@dataclass
class InMemoryArtifactStore:
    _store: dict[str, ReexecutionBundle] = field(default_factory=dict)

    def store(self, ref: CorrectnessArtifactRef, bundle: ReexecutionBundle) -> None:
        self._store[ref.artifact_id] = bundle

    def get(self, artifact_ref: CorrectnessArtifactRef) -> ReexecutionBundle | None:
        return self._store.get(artifact_ref.artifact_id)


def _toy_rerun(bundle: ReexecutionBundle) -> str:
    """Deterministic rerun that always matches."""
    return bundle.output_digest


def build_runtime() -> Runtime:
    """Build the full monitoring runtime with toy adapters."""
    artifact_store = InMemoryArtifactStore()

    prover = ProverRuntime(
        scheduler=ToyScheduler(),
        inference=ToyInference(),
        control=ToyControl(),
        artifacts=artifact_store,
    )

    participants = [
        prover,
        CorrectnessVerifier(
            strategy=ReexecutionStrategy(rerun=_toy_rerun),
            sample_fraction=1.0,
        ),
        ScheduleCoverageVerifier(),
        SanitizationFrequencyVerifier(max_gap_seconds=5.0),
        NetworkUtilizationVerifier(),
        CovertCapacityEstimator(
            sram_per_gpu_bytes=8,
            num_gpus=1,
            excess_capacity_bytes=16,
        ),
        RemoteAttestationVerifier(
            trusted_code_digests=frozenset({"code-digest-1"}),
            trusted_config_digests=frozenset({"config-digest-1"}),
        ),
        ComplianceVerifier(approved_models=frozenset({"model-a"})),
        DisclosurePublisher(),
    ]

    return Runtime(
        log=EventLog(),
        participants=participants,  # type: ignore[arg-type]
        now=0.0,
    )


def run_example() -> Runtime:
    """Run the simple inference example and return the runtime."""
    runtime = build_runtime()
    prover = runtime.participants[0]
    assert isinstance(prover, ProverRuntime)

    # Seed: machine added
    runtime.emit(
        MachineAddedEvent(
            event_id=runtime.make_event_id("machine-added"),
            timestamp=runtime.now,
            principal=Principal.PROVER,
            source="prover_runtime",
            readers=TRANSCRIPT_READERS,
            machine_id="gpu-node-0",
            machine_kind="gpu",
        )
    )

    # Seed: workload started
    runtime.emit(
        WorkloadStartedEvent(
            event_id=runtime.make_event_id("workload-started"),
            timestamp=runtime.now,
            principal=Principal.PROVER,
            source="prover_runtime",
            readers=TRANSCRIPT_READERS,
            workload_id="w1",
            machine_id="gpu-node-0",
        )
    )

    # Seed: remote attestation
    runtime.emit(
        RemoteAttestationClaimedEvent(
            event_id=runtime.make_event_id("attestation"),
            timestamp=runtime.now,
            principal=Principal.PROVER,
            source="prover_runtime",
            readers=TRANSCRIPT_READERS,
            attester_id="tee-0",
            code_digest="code-digest-1",
            config_digest="config-digest-1",
        )
    )

    # Seed: sanitization events (within threshold)
    runtime.emit(
        MemorySanitizationPerformedEvent(
            event_id=runtime.make_event_id("sanitization"),
            timestamp=runtime.now,
            principal=Principal.PROVER,
            source="prover_runtime",
            readers=TRANSCRIPT_READERS,
            machine_id="gpu-node-0",
            epoch=1,
            merkle_root="root-1",
            spot_check_passed=True,
        )
    )
    runtime.now += 3.0
    runtime.emit(
        MemorySanitizationPerformedEvent(
            event_id=runtime.make_event_id("sanitization"),
            timestamp=runtime.now,
            principal=Principal.PROVER,
            source="prover_runtime",
            readers=TRANSCRIPT_READERS,
            machine_id="gpu-node-0",
            epoch=2,
            merkle_root="root-2",
            spot_check_passed=True,
        )
    )

    # Dispatch seed events
    runtime.dispatch_until_quiescent()

    # Prover performs one toy inference
    prover.perform_inference(
        runtime,
        request_id="req-1",
        model_id="model-a",
        input_bytes=b"hello world",
    )

    # Dispatch the inference claim
    runtime.dispatch_until_quiescent()

    # Tick to trigger verifier sampling, evaluation, compliance, and disclosure
    runtime.tick(delta=1.0)

    return runtime


if __name__ == "__main__":
    from ccm import render_summary

    rt = run_example()
    print(render_summary(rt.log))
