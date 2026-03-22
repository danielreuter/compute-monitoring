"""
Simple inference example: demonstrates the full monitoring system in one process.

The example script acts as "the real world" — it pushes records into the prover's
adapters to simulate compute activity, then advances the runtime clock. The prover
drains those adapters on each tick and emits the protocol-required transcript events.
The verifiers consume the transcript and produce verification/compliance/disclosure.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from event_log import EventLog, Role, TRANSCRIPT_READERS
from protocols.transparency.correctness import (
    CorrectnessArtifactRef,
    CorrectnessVerifier,
    ReexecutionBundle,
    ReexecutionStrategy,
)
from protocols.transparency.utilization import (
    CovertCapacityEstimator,
    MachineAddedEvent,
    NetworkUtilizationVerifier,
    SanitizationFrequencyVerifier,
    ScheduleCoverageVerifier,
)
from protocols.transparency.remote_attestation import (
    RemoteAttestationClaimedEvent,
    RemoteAttestationVerifier,
)
from protocols.compliance import ComplianceVerifier
from protocols.disclosure import DisclosurePublisher
from runtime.engine import Runtime
from runtime.prover import ProverRuntime
from tests._toy_adapters import (
    ToyControlAdapter,
    ToyInferenceAdapter,
    ToySanitizationAdapter,
    ToySchedulerAdapter,
)


def _toy_rerun(bundle: ReexecutionBundle) -> str:
    """Deterministic rerun that always matches."""
    return bundle.output_digest


def build_runtime() -> tuple[
    Runtime, ToyInferenceAdapter, ToySchedulerAdapter, ToySanitizationAdapter
]:
    """Build the full monitoring runtime with toy adapters."""
    inference = ToyInferenceAdapter()
    scheduler = ToySchedulerAdapter()
    sanitization = ToySanitizationAdapter()
    control = ToyControlAdapter()

    prover = ProverRuntime(
        inference=inference,
        scheduler=scheduler,
        sanitization=sanitization,
        control=control,
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

    runtime = Runtime(
        log=EventLog(),
        participants=participants,  # type: ignore[arg-type]
        now=0.0,
    )
    return runtime, inference, scheduler, sanitization


def run_example() -> Runtime:
    """Run the simple inference example and return the runtime."""
    runtime, inference, scheduler, sanitization = build_runtime()

    # --- The "real world" pushes activity into the adapters ---

    # Machine comes online (emitted directly as a seed event — machine inventory
    # isn't periodic, it's a one-time bootstrap)
    runtime.emit(
        MachineAddedEvent(
            event_id=runtime.make_event_id("machine-added"),
            timestamp=runtime.now,
            writer=Role.PROVER,
            readers=TRANSCRIPT_READERS,
            machine_id="gpu-node-0",
            machine_kind="gpu",
        )
    )

    # Remote attestation (also a seed — happens at boot, not periodically)
    runtime.emit(
        RemoteAttestationClaimedEvent(
            event_id=runtime.make_event_id("attestation"),
            timestamp=runtime.now,
            writer=Role.PROVER,
            readers=TRANSCRIPT_READERS,
            attester_id="tee-0",
            code_digest="code-digest-1",
            config_digest="config-digest-1",
        )
    )
    runtime.dispatch_until_quiescent()

    # Workload starts, sanitization happens, inference completes
    scheduler.start_workload("w1", "gpu-node-0")
    sanitization.record_sanitization("gpu-node-0", epoch=1, merkle_root="root-1")
    inference.record_inference("req-1", "model-a", b"hello world")

    # First tick: prover drains adapters, verifiers begin sampling
    runtime.tick(delta=1.0)

    # More sanitization
    sanitization.record_sanitization("gpu-node-0", epoch=2, merkle_root="root-2")

    # Second tick: correctness artifact exchange completes, compliance + disclosure
    runtime.tick(delta=1.0)

    return runtime


if __name__ == "__main__":
    from ccm import render_summary

    rt = run_example()
    print(render_summary(rt.log))
