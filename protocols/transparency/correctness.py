"""
Correctness transparency: inference claims, reexecution verification, and artifact exchange.
"""

from __future__ import annotations

import hashlib
import random
from dataclasses import dataclass, field
from typing import Callable, ClassVar, Protocol

from event_log import (
    Event,
    EventView,
    Role,
    TRANSCRIPT_READERS,
    VERIFICATION_READERS,
)
from runtime.base import Participant
from runtime.engine import Runtime


# --- Types ---


@dataclass(frozen=True)
class CorrectnessArtifactRef:
    artifact_id: str


@dataclass(frozen=True)
class ReexecutionBundle:
    model_id: str
    input_bytes: bytes
    output_digest: str
    engine_digest: str
    metadata: dict[str, str]


# --- Transcript events ---


@dataclass(frozen=True, kw_only=True)
class InferenceClaimedEvent(Event):
    request_id: str
    model_id: str
    input_digest: str
    output_digest: str
    artifact_ref: CorrectnessArtifactRef

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


# --- Verification events ---


@dataclass(frozen=True, kw_only=True)
class CorrectnessCheckRequestedEvent(Event):
    session_id: str
    request_id: str
    artifact_ref: CorrectnessArtifactRef
    strategy: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class CorrectnessArtifactPublishedEvent(Event):
    session_id: str
    in_reply_to: str
    artifact_ref: CorrectnessArtifactRef
    bundle: ReexecutionBundle

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class CorrectnessCheckTimedOutEvent(Event):
    session_id: str
    request_id: str
    strategy: str
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class CorrectnessEvaluatedEvent(Event):
    session_id: str
    request_id: str
    strategy: str
    passed: bool
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


# --- Strategy interface ---


class CorrectnessStrategy(Protocol):
    name: str

    def evaluate(self, bundle: ReexecutionBundle) -> tuple[bool, str]: ...


@dataclass
class ReexecutionStrategy:
    name: str = "reexecution"
    rerun: Callable[[ReexecutionBundle], str] = lambda bundle: ""

    def evaluate(self, bundle: ReexecutionBundle) -> tuple[bool, str]:
        recomputed_digest = self.rerun(bundle)
        passed = recomputed_digest == bundle.output_digest
        details = "match" if passed else f"mismatch: expected {bundle.output_digest}, got {recomputed_digest}"
        return passed, details


# --- Prover participant ---


@dataclass
class CorrectnessProver:
    writer: Role = field(default=Role.PROVER, init=False)

    _pending: list[tuple[str, str, str, str, CorrectnessArtifactRef]] = field(
        default_factory=list, init=False, repr=False
    )
    _bundles: dict[str, ReexecutionBundle] = field(
        default_factory=dict, init=False, repr=False
    )

    def report_inference(
        self,
        request_id: str,
        model_id: str,
        input_bytes: bytes,
    ) -> CorrectnessArtifactRef:
        """Record an inference completion. Returns the artifact ref."""
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
        self._pending.append((request_id, model_id, input_digest, output_digest, ref))
        return ref

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        if isinstance(event, CorrectnessCheckRequestedEvent):
            return self._handle_correctness_check(event, runtime)
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        events: list[Event] = []
        for request_id, model_id, input_digest, output_digest, ref in self._pending:
            events.append(
                InferenceClaimedEvent(
                    event_id=runtime.make_event_id("inference-claimed"),
                    timestamp=runtime.now,
                    writer=Role.PROVER,
                    readers=TRANSCRIPT_READERS,
                    request_id=request_id,
                    model_id=model_id,
                    input_digest=input_digest,
                    output_digest=output_digest,
                    artifact_ref=ref,
                )
            )
        self._pending.clear()
        return events

    def _handle_correctness_check(
        self, event: CorrectnessCheckRequestedEvent, runtime: Runtime
    ) -> list[Event]:
        bundle = self._bundles.get(event.artifact_ref.artifact_id)
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


# --- Verifier participant ---


@dataclass
class CorrectnessVerifier:
    writer: Role = field(default=Role.VERIFIER, init=False)
    strategy: CorrectnessStrategy
    sample_fraction: float = 0.1
    timeout_ticks: float = 5.0

    _pending_sessions: dict[str, tuple[str, float]] = field(
        default_factory=dict, init=False, repr=False
    )
    _verified_request_ids: set[str] = field(default_factory=set, init=False, repr=False)

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        if isinstance(event, CorrectnessArtifactPublishedEvent):
            return self._evaluate_artifact(event, runtime)
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        events: list[Event] = []

        # Sample unverified claims
        claims = [
            e
            for e in runtime.log.of_type(InferenceClaimedEvent)
            if e.request_id not in self._verified_request_ids
            and e.request_id not in {rid for rid, _ in self._pending_sessions.values()}
        ]
        if claims:
            sample_size = max(1, int(len(claims) * self.sample_fraction))
            sample = random.sample(claims, k=min(sample_size, len(claims)))
            for claim in sample:
                session_id = runtime.make_session_id("correctness")
                self._pending_sessions[session_id] = (claim.request_id, runtime.now)
                events.append(
                    CorrectnessCheckRequestedEvent(
                        event_id=runtime.make_event_id("correctness-check"),
                        timestamp=runtime.now,
                        writer=Role.VERIFIER,
                        readers=VERIFICATION_READERS,
                        session_id=session_id,
                        request_id=claim.request_id,
                        artifact_ref=claim.artifact_ref,
                        strategy=self.strategy.name,
                    )
                )

        # Check timeouts
        timed_out = []
        for session_id, (request_id, start_time) in self._pending_sessions.items():
            if runtime.now - start_time >= self.timeout_ticks:
                timed_out.append(session_id)
                events.append(
                    CorrectnessCheckTimedOutEvent(
                        event_id=runtime.make_event_id("correctness-timeout"),
                        timestamp=runtime.now,
                        writer=Role.VERIFIER,
                        readers=VERIFICATION_READERS,
                        session_id=session_id,
                        request_id=request_id,
                        strategy=self.strategy.name,
                        details=f"timed out after {self.timeout_ticks} ticks",
                    )
                )
        for session_id in timed_out:
            del self._pending_sessions[session_id]

        return events

    def _evaluate_artifact(
        self, event: CorrectnessArtifactPublishedEvent, runtime: Runtime
    ) -> list[Event]:
        session_id = event.session_id
        if session_id not in self._pending_sessions:
            return []

        request_id, _ = self._pending_sessions.pop(session_id)
        self._verified_request_ids.add(request_id)

        passed, details = self.strategy.evaluate(event.bundle)
        return [
            CorrectnessEvaluatedEvent(
                event_id=runtime.make_event_id("correctness-evaluated"),
                timestamp=runtime.now,
                writer=Role.VERIFIER,
                readers=VERIFICATION_READERS,
                session_id=session_id,
                request_id=request_id,
                strategy=self.strategy.name,
                passed=passed,
                details=details,
            )
        ]
