"""
Zero-knowledge-based correctness protocol.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Callable

from event_log import Event, Side, TRANSCRIPT_READERS, VERIFICATION_READERS
from runtime.engine import Runtime

from .common import (
    CorrectnessCheckRequestedEvent,
    CorrectnessCheckTimedOutEvent,
    CorrectnessCommitmentRef,
    CorrectnessEvaluatedEvent,
    InferenceClaimedEvent,
    WorkloadAddress,
    short_digest,
)


@dataclass(frozen=True)
class ZeroKnowledgeProofBundle:
    proof_system: str
    verification_key_id: str
    public_input_digest: str
    output_digest: str
    proof_bytes: bytes
    metadata: dict[str, str]


@dataclass(frozen=True, kw_only=True)
class ZeroKnowledgeProofSubmittedEvent(Event):
    session_id: str
    in_reply_to: str
    commitment_ref: CorrectnessCommitmentRef
    proof_bundle: ZeroKnowledgeProofBundle

    views = CorrectnessEvaluatedEvent.views


@dataclass
class ZeroKnowledgeProver:
    writer: Side = field(default=Side.PROVER, init=False)

    _pending: list[
        tuple[
            str,
            str,
            str,
            str,
            CorrectnessCommitmentRef,
            WorkloadAddress,
            frozenset[str],
        ]
    ] = field(default_factory=list, init=False, repr=False)
    _proofs: dict[str, ZeroKnowledgeProofBundle] = field(default_factory=dict, init=False, repr=False)

    def report_inference(
        self,
        request_id: str,
        model_id: str,
        input_bytes: bytes,
        *,
        output_bytes: bytes | None = None,
        proof_bytes: bytes | None = None,
        workload_kind: str = "inference_request",
        workload_address: str | None = None,
        commitment_scheme: str = "execution-transcript",
        proof_system: str = "dummy-zkvm",
        verification_key_id: str = "vk-1",
        metadata: dict[str, str] | None = None,
    ) -> CorrectnessCommitmentRef:
        output_payload = output_bytes or f"output-for-{request_id}".encode()
        output_digest = short_digest(output_payload)
        input_digest = short_digest(input_bytes)
        commitment_ref = CorrectnessCommitmentRef(
            commitment_id=f"commitment-{request_id}",
            scheme=commitment_scheme,
        )
        subject = WorkloadAddress(
            workload_kind=workload_kind,
            address=workload_address or request_id,
        )
        proof_bundle = ZeroKnowledgeProofBundle(
            proof_system=proof_system,
            verification_key_id=verification_key_id,
            public_input_digest=input_digest,
            output_digest=output_digest,
            proof_bytes=proof_bytes or f"proof-for-{request_id}".encode(),
            metadata=metadata or {},
        )
        self._proofs[commitment_ref.commitment_id] = proof_bundle
        self._pending.append(
            (
                request_id,
                model_id,
                input_digest,
                output_digest,
                commitment_ref,
                subject,
                frozenset({"zero_knowledge"}),
            )
        )
        return commitment_ref

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        if not isinstance(event, CorrectnessCheckRequestedEvent):
            return []
        if event.mechanism != "zero_knowledge":
            return []

        proof_bundle = self._proofs.get(event.commitment_ref.commitment_id)
        if proof_bundle is None:
            return []
        return [
            ZeroKnowledgeProofSubmittedEvent(
                event_id=runtime.make_event_id("zk-proof"),
                timestamp=runtime.now,
                writer=Side.PROVER,
                readers=VERIFICATION_READERS,
                session_id=event.session_id,
                in_reply_to=event.event_id,
                commitment_ref=event.commitment_ref,
                proof_bundle=proof_bundle,
            )
        ]

    def on_tick(self, runtime: Runtime) -> list[Event]:
        events: list[Event] = []
        for (
            request_id,
            model_id,
            input_digest,
            output_digest,
            commitment_ref,
            subject,
            available_mechanisms,
        ) in self._pending:
            events.append(
                InferenceClaimedEvent(
                    event_id=runtime.make_event_id("inference-claimed"),
                    timestamp=runtime.now,
                    writer=Side.PROVER,
                    readers=TRANSCRIPT_READERS,
                    request_id=request_id,
                    model_id=model_id,
                    input_digest=input_digest,
                    output_digest=output_digest,
                    commitment_ref=commitment_ref,
                    subject=subject,
                    available_mechanisms=available_mechanisms,
                )
            )
        self._pending.clear()
        return events


@dataclass
class ZeroKnowledgeVerifier:
    verify_proof: Callable[[ZeroKnowledgeProofBundle], tuple[bool, str]]
    sample_fraction: float = 0.1
    timeout_ticks: float = 5.0
    random_seed: int = 0
    writer: Side = field(default=Side.VERIFIER, init=False)

    _pending_sessions: dict[str, tuple[str, float]] = field(default_factory=dict, init=False, repr=False)
    _verified_request_ids: set[str] = field(default_factory=set, init=False, repr=False)
    _rng: random.Random = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self._rng = random.Random(self.random_seed)

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        if not isinstance(event, ZeroKnowledgeProofSubmittedEvent):
            return []

        session_id = event.session_id
        if session_id not in self._pending_sessions:
            return []

        request_id, _ = self._pending_sessions.pop(session_id)
        self._verified_request_ids.add(request_id)
        passed, details = self.verify_proof(event.proof_bundle)
        return [
            CorrectnessEvaluatedEvent(
                event_id=runtime.make_event_id("correctness-evaluated"),
                timestamp=runtime.now,
                writer=Side.VERIFIER,
                readers=VERIFICATION_READERS,
                session_id=session_id,
                request_id=request_id,
                mechanism="zero_knowledge",
                passed=passed,
                details=details,
            )
        ]

    def on_tick(self, runtime: Runtime) -> list[Event]:
        events = self._issue_checks(runtime)
        events.extend(self._expire_checks(runtime))
        return events

    def _issue_checks(self, runtime: Runtime) -> list[Event]:
        claims = [
            event
            for event in runtime.log.of_type(InferenceClaimedEvent)
            if "zero_knowledge" in event.available_mechanisms
            and event.request_id not in self._verified_request_ids
            and event.request_id not in {request_id for request_id, _ in self._pending_sessions.values()}
        ]
        if not claims or self.sample_fraction <= 0:
            return []

        sample_size = int(len(claims) * self.sample_fraction)
        if sample_size == 0:
            sample_size = 1
        sample = self._rng.sample(claims, k=min(sample_size, len(claims)))

        events: list[Event] = []
        for claim in sample:
            session_id = runtime.make_session_id("correctness")
            self._pending_sessions[session_id] = (claim.request_id, runtime.now)
            events.append(
                CorrectnessCheckRequestedEvent(
                    event_id=runtime.make_event_id("correctness-check"),
                    timestamp=runtime.now,
                    writer=Side.VERIFIER,
                    readers=VERIFICATION_READERS,
                    session_id=session_id,
                    request_id=claim.request_id,
                    mechanism="zero_knowledge",
                    challenge_token=f"sample:{session_id}",
                    commitment_ref=claim.commitment_ref,
                    subject=claim.subject,
                )
            )
        return events

    def _expire_checks(self, runtime: Runtime) -> list[Event]:
        events: list[Event] = []
        timed_out: list[str] = []
        for session_id, (request_id, start_time) in self._pending_sessions.items():
            if runtime.now - start_time < self.timeout_ticks:
                continue
            timed_out.append(session_id)
            events.append(
                CorrectnessCheckTimedOutEvent(
                    event_id=runtime.make_event_id("correctness-timeout"),
                    timestamp=runtime.now,
                    writer=Side.VERIFIER,
                    readers=VERIFICATION_READERS,
                    session_id=session_id,
                    request_id=request_id,
                    mechanism="zero_knowledge",
                    details=f"timed out after {self.timeout_ticks} ticks",
                )
            )
        for session_id in timed_out:
            del self._pending_sessions[session_id]
        return events
