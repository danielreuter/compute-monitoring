from __future__ import annotations

import unittest

from event_log import EventLog, Role, TRANSCRIPT_READERS
from protocols.transparency.utilization import (
    MemorySanitizationPerformedEvent,
    SanitizationFrequencyEvaluatedEvent,
    SanitizationFrequencyVerifier,
)
from runtime.engine import Runtime


def _make_attestation(event_id: str, timestamp: float) -> MemorySanitizationPerformedEvent:
    return MemorySanitizationPerformedEvent(
        event_id=event_id, timestamp=timestamp,
        writer=Role.PROVER, readers=TRANSCRIPT_READERS,
        machine_id="gpu-0", epoch=1, merkle_root="root",
        spot_check_passed=True,
    )


class SanitizationFrequencyTest(unittest.TestCase):
    def test_passes_when_gaps_within_threshold(self) -> None:
        verifier = SanitizationFrequencyVerifier(max_gap_seconds=5.0)
        runtime = Runtime(
            log=EventLog(),
            participants=[verifier],  # type: ignore[list-item]
        )

        runtime.emit(_make_attestation("a1", 0.0))
        runtime.emit(_make_attestation("a2", 4.0))
        runtime.dispatch_until_quiescent()

        runtime.tick()

        events = runtime.log.of_type(SanitizationFrequencyEvaluatedEvent)
        self.assertEqual(len(events), 1)
        self.assertTrue(events[0].passed)
        self.assertEqual(events[0].gap_count, 0)

    def test_fails_when_gap_exceeds_threshold(self) -> None:
        verifier = SanitizationFrequencyVerifier(max_gap_seconds=5.0)
        runtime = Runtime(
            log=EventLog(),
            participants=[verifier],  # type: ignore[list-item]
        )

        runtime.emit(_make_attestation("a1", 0.0))
        runtime.emit(_make_attestation("a2", 7.0))
        runtime.dispatch_until_quiescent()

        runtime.tick()

        events = runtime.log.of_type(SanitizationFrequencyEvaluatedEvent)
        self.assertEqual(len(events), 1)
        self.assertFalse(events[0].passed)
        self.assertEqual(events[0].gap_count, 1)


if __name__ == "__main__":
    unittest.main()
