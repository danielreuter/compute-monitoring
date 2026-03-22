"""
Shared correctness transcript and verification events.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import ClassVar

from event_log import Event, EventView


@dataclass(frozen=True)
class CorrectnessCommitmentRef:
    commitment_id: str
    scheme: str = "opaque"

    @property
    def artifact_id(self) -> str:
        return self.commitment_id


@dataclass(frozen=True)
class WorkloadAddress:
    workload_kind: str
    address: str


@dataclass(frozen=True, kw_only=True)
class InferenceClaimedEvent(Event):
    request_id: str
    model_id: str
    input_digest: str
    output_digest: str
    commitment_ref: CorrectnessCommitmentRef
    subject: WorkloadAddress
    available_mechanisms: frozenset[str] = frozenset({"reexecution"})

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


@dataclass(frozen=True, kw_only=True)
class CorrectnessCheckRequestedEvent(Event):
    session_id: str
    request_id: str
    mechanism: str
    challenge_token: str
    commitment_ref: CorrectnessCommitmentRef
    subject: WorkloadAddress

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class CorrectnessCheckTimedOutEvent(Event):
    session_id: str
    request_id: str
    mechanism: str
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


@dataclass(frozen=True, kw_only=True)
class CorrectnessEvaluatedEvent(Event):
    session_id: str
    request_id: str
    mechanism: str
    passed: bool
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


def short_digest(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()[:16]
