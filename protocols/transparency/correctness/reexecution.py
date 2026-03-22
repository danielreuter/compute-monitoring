"""
Reexecution-based correctness protocol.
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
class ReexecutionBundle:
    model_id: str
    input_bytes: bytes
    output_digest: str
    engine_digest: str
    metadata: dict[str, str]


@dataclass(frozen=True, kw_only=True)
class ReexecutionEvidencePublishedEvent(Event):
    session_id: str
    in_reply_to: str
    commitment_ref: CorrectnessCommitmentRef
    bundle: ReexecutionBundle


    views = CorrectnessEvaluatedEvent.views


@dataclass
class ReexecutionProver:
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
    _bundles: dict[str, ReexecutionBundle] = field(default_factory=dict, init=False, repr=False)

    def report_inference(
        self,
        request_id: str,
        model_id: str,
        input_bytes: bytes,
        *,
        output_bytes: bytes | None = None,
        workload_kind: str = "inference_request",
        workload_address: str | None = None,
        commitment_scheme: str = "execution-transcript",
        engine_digest: str = "",
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
        bundle = ReexecutionBundle(
            model_id=model_id,
            input_bytes=input_bytes,
            output_digest=output_digest,
            engine_digest=engine_digest,
            metadata=metadata or {},
        )
        self._bundles[commitment_ref.commitment_id] = bundle
        self._pending.append(
            (
                request_id,
                model_id,
                input_digest,
                output_digest,
                commitment_ref,
                subject,
                frozenset({"reexecution"}),
            )
        )
        return commitment_ref

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        if not isinstance(event, CorrectnessCheckRequestedEvent):
            return []
        if event.mechanism != "reexecution":
            return []

        bundle = self._bundles.get(event.commitment_ref.commitment_id)
        if bundle is None:
            return []
        return [
            ReexecutionEvidencePublishedEvent(
                event_id=runtime.make_event_id("reexecution-evidence"),
                timestamp=runtime.now,
                writer=Side.PROVER,
                readers=VERIFICATION_READERS,
                session_id=event.session_id,
                in_reply_to=event.event_id,
                commitment_ref=event.commitment_ref,
                bundle=bundle,
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
class ReexecutionVerifier:
    rerun: Callable[[ReexecutionBundle], str]
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
        if not isinstance(event, ReexecutionEvidencePublishedEvent):
            return []

        session_id = event.session_id
        if session_id not in self._pending_sessions:
            return []

        request_id, _ = self._pending_sessions.pop(session_id)
        self._verified_request_ids.add(request_id)
        recomputed_digest = self.rerun(event.bundle)
        passed = recomputed_digest == event.bundle.output_digest
        details = (
            "match"
            if passed
            else f"mismatch: expected {event.bundle.output_digest}, got {recomputed_digest}"
        )
        return [
            CorrectnessEvaluatedEvent(
                event_id=runtime.make_event_id("correctness-evaluated"),
                timestamp=runtime.now,
                writer=Side.VERIFIER,
                readers=VERIFICATION_READERS,
                session_id=session_id,
                request_id=request_id,
                mechanism="reexecution",
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
            if "reexecution" in event.available_mechanisms
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
                    mechanism="reexecution",
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
                    mechanism="reexecution",
                    details=f"timed out after {self.timeout_ticks} ticks",
                )
            )
        for session_id in timed_out:
            del self._pending_sessions[session_id]
        return events
