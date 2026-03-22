"""
Shared toy adapter implementations for tests.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from protocols.transparency.correctness import CorrectnessArtifactRef, ReexecutionBundle
from runtime.prover import (
    InferenceRecord,
    ProverRuntime,
    SanitizationRecord,
    SchedulerRecord,
)


@dataclass
class ToyInferenceAdapter:
    """Accumulates inference records; drained by ProverRuntime.on_tick."""
    _pending: list[InferenceRecord] = field(default_factory=list)
    _bundles: dict[str, ReexecutionBundle] = field(default_factory=dict)

    def pending_claims(self) -> list[InferenceRecord]:
        claims = list(self._pending)
        self._pending.clear()
        return claims

    def get_bundle(self, artifact_ref: CorrectnessArtifactRef) -> ReexecutionBundle | None:
        return self._bundles.get(artifact_ref.artifact_id)

    def stop_engine(self) -> None:
        pass

    def record_inference(
        self, request_id: str, model_id: str, input_bytes: bytes,
    ) -> InferenceRecord:
        """Simulate an inference completing — adds a pending claim."""
        output = f"output-for-{request_id}".encode()
        output_digest = hashlib.sha256(output).hexdigest()[:16]
        input_digest = hashlib.sha256(input_bytes).hexdigest()[:16]
        ref = CorrectnessArtifactRef(artifact_id=f"artifact-{request_id}")
        bundle = ReexecutionBundle(
            model_id=model_id,
            input_bytes=input_bytes,
            output_digest=output_digest,
            engine_digest="",
            metadata={},
        )
        self._bundles[ref.artifact_id] = bundle
        record = InferenceRecord(
            request_id=request_id,
            model_id=model_id,
            input_digest=input_digest,
            output_digest=output_digest,
            artifact_ref=ref,
            bundle=bundle,
        )
        self._pending.append(record)
        return record


@dataclass
class ToySchedulerAdapter:
    _pending: list[SchedulerRecord] = field(default_factory=list)

    def pending_changes(self) -> list[SchedulerRecord]:
        changes = list(self._pending)
        self._pending.clear()
        return changes

    def start_workload(self, workload_id: str, machine_id: str) -> None:
        self._pending.append(SchedulerRecord(workload_id=workload_id, machine_id=machine_id, started=True))

    def stop_workload(self, workload_id: str, machine_id: str) -> None:
        self._pending.append(SchedulerRecord(workload_id=workload_id, machine_id=machine_id, started=False))


@dataclass
class ToySanitizationAdapter:
    _pending: list[SanitizationRecord] = field(default_factory=list)

    def pending_attestations(self) -> list[SanitizationRecord]:
        attestations = list(self._pending)
        self._pending.clear()
        return attestations

    def record_sanitization(
        self, machine_id: str, epoch: int, merkle_root: str, spot_check_passed: bool = True,
    ) -> None:
        self._pending.append(SanitizationRecord(
            machine_id=machine_id, epoch=epoch, merkle_root=merkle_root,
            spot_check_passed=spot_check_passed,
        ))


@dataclass
class ToyControlAdapter:
    def handle_command(self, command: str, payload: dict[str, object]) -> str:
        return "ok"


def make_adapters() -> tuple[ToyInferenceAdapter, ToySchedulerAdapter, ToySanitizationAdapter, ToyControlAdapter]:
    return ToyInferenceAdapter(), ToySchedulerAdapter(), ToySanitizationAdapter(), ToyControlAdapter()


def make_prover(
    inference: ToyInferenceAdapter | None = None,
    scheduler: ToySchedulerAdapter | None = None,
    sanitization: ToySanitizationAdapter | None = None,
    control: ToyControlAdapter | None = None,
) -> ProverRuntime:
    return ProverRuntime(
        inference=inference or ToyInferenceAdapter(),
        scheduler=scheduler or ToySchedulerAdapter(),
        sanitization=sanitization or ToySanitizationAdapter(),
        control=control or ToyControlAdapter(),
    )
