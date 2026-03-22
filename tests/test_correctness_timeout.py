from __future__ import annotations

import unittest
from dataclasses import dataclass

from event_log import Event, EventLog, Side, TRANSCRIPT_READERS
from protocols.transparency.correctness import (
    CorrectnessArtifactRef,
    CorrectnessCheckRequestedEvent,
    CorrectnessCheckTimedOutEvent,
    CorrectnessVerifier,
    InferenceClaimedEvent,
    ReexecutionStrategy,
)
from runtime.engine import Runtime


@dataclass
class NoOpParticipant:
    """A prover that never responds to correctness checks."""
    writer: Side = Side.PROVER

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        return []


class CorrectnessTimeoutTest(unittest.TestCase):
    def test_timeout_after_ticks(self) -> None:
        strategy = ReexecutionStrategy(rerun=lambda b: "")
        verifier = CorrectnessVerifier(
            strategy=strategy, sample_fraction=1.0, timeout_ticks=3.0,
        )
        runtime = Runtime(
            log=EventLog(),
            participants=[NoOpParticipant(), verifier],  # type: ignore[list-item]
        )

        # Emit a claim
        runtime.emit(
            InferenceClaimedEvent(
                event_id="claim-1", timestamp=0.0,
                writer=Side.PROVER, readers=TRANSCRIPT_READERS,
                request_id="req-1", model_id="model-a",
                input_digest="in", output_digest="out",
                artifact_ref=CorrectnessArtifactRef(artifact_id="a1"),
            )
        )
        runtime.dispatch_until_quiescent()

        # First tick: verifier requests check
        runtime.tick()
        checks = runtime.log.of_type(CorrectnessCheckRequestedEvent)
        self.assertEqual(len(checks), 1)
        timeouts = runtime.log.of_type(CorrectnessCheckTimedOutEvent)
        self.assertEqual(len(timeouts), 0)

        # Advance time past timeout
        runtime.tick(delta=2.0)
        runtime.tick(delta=2.0)

        timeouts = runtime.log.of_type(CorrectnessCheckTimedOutEvent)
        self.assertEqual(len(timeouts), 1)
        self.assertEqual(timeouts[0].request_id, "req-1")
        self.assertIn("timed out", timeouts[0].details)


if __name__ == "__main__":
    unittest.main()
