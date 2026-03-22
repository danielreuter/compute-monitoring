"""
Shared toy adapter implementations for tests.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from event_log import Event
from protocols.transparency.correctness import CorrectnessArtifactRef, ReexecutionBundle
from runtime.prover import (
    CorrectnessArtifactStore,
    InferenceRunResult,
    ProverRuntime,
)


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


def make_artifact_store() -> InMemoryArtifactStore:
    return InMemoryArtifactStore()


def make_prover(
    artifacts: CorrectnessArtifactStore | None = None,
) -> ProverRuntime:
    return ProverRuntime(
        scheduler=ToyScheduler(),
        inference=ToyInference(),
        control=ToyControl(),
        artifacts=artifacts or make_artifact_store(),
    )
