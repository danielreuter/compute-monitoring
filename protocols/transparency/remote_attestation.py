"""
Remote attestation transparency: TEE attestation claims and verification.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import ClassVar

from event_log import (
    Event,
    EventView,
    Role,
    VERIFICATION_READERS,
)
from runtime.base import Participant
from runtime.engine import Runtime


# --- Events ---


@dataclass(frozen=True, kw_only=True)
class RemoteAttestationClaimedEvent(Event):
    attester_id: str
    code_digest: str
    config_digest: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.TRANSCRIPT})


@dataclass(frozen=True, kw_only=True)
class RemoteAttestationEvaluatedEvent(Event):
    passed: bool
    details: str

    views: ClassVar[frozenset[EventView]] = frozenset({EventView.VERIFICATION})


# --- Participant ---


@dataclass
class RemoteAttestationVerifier:
    writer: Role = field(default=Role.VERIFIER, init=False)
    trusted_code_digests: frozenset[str] = frozenset()
    trusted_config_digests: frozenset[str] = frozenset()

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        if isinstance(event, RemoteAttestationClaimedEvent):
            return self._evaluate(event, runtime)
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        return []

    def _evaluate(
        self, event: RemoteAttestationClaimedEvent, runtime: Runtime
    ) -> list[Event]:
        code_ok = (
            not self.trusted_code_digests
            or event.code_digest in self.trusted_code_digests
        )
        config_ok = (
            not self.trusted_config_digests
            or event.config_digest in self.trusted_config_digests
        )
        passed = code_ok and config_ok
        if passed:
            details = "attestation verified"
        else:
            failures = []
            if not code_ok:
                failures.append(f"untrusted code digest: {event.code_digest}")
            if not config_ok:
                failures.append(f"untrusted config digest: {event.config_digest}")
            details = "; ".join(failures)

        return [
            RemoteAttestationEvaluatedEvent(
                event_id=runtime.make_event_id("attestation-evaluated"),
                timestamp=runtime.now,
                writer=Role.VERIFIER,
                readers=VERIFICATION_READERS,
                passed=passed,
                details=details,
            )
        ]
