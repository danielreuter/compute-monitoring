from __future__ import annotations

import unittest

from event_log import EventLog, Side, TRANSCRIPT_READERS
from protocols.transparency.correctness import (
    CorrectnessArtifactPublishedEvent,
    CorrectnessArtifactRef,
    CorrectnessCheckRequestedEvent,
    CorrectnessEvaluatedEvent,
    CorrectnessProver,
    CorrectnessVerifier,
    InferenceClaimedEvent,
    ReexecutionBundle,
    ReexecutionStrategy,
)
from runtime.engine import Runtime


class CorrectnessReexecutionFlowTest(unittest.TestCase):
    def _build_runtime(self, *, rerun_digest: str = "out-digest") -> Runtime:
        prover = CorrectnessProver()

        # Simulate an inference completing
        ref = prover.report_inference("req-1", "model-a", b"hello")
        # Override the bundle with a known digest so we can control match/mismatch
        known_bundle = ReexecutionBundle(
            model_id="model-a",
            input_bytes=b"hello",
            output_digest="out-digest",
            engine_digest="",
            metadata={},
        )
        prover._bundles[ref.artifact_id] = known_bundle

        strategy = ReexecutionStrategy(rerun=lambda b: rerun_digest)
        verifier = CorrectnessVerifier(strategy=strategy, sample_fraction=1.0)

        runtime = Runtime(
            log=EventLog(),
            participants=[prover, verifier],  # type: ignore[list-item]
        )

        # First tick: prover emits InferenceClaimedEvent,
        # verifier samples -> CorrectnessCheckRequestedEvent,
        # prover responds -> CorrectnessArtifactPublishedEvent,
        # verifier evaluates -> CorrectnessEvaluatedEvent
        runtime.tick()
        return runtime

    def test_matching_bundle_passes(self) -> None:
        runtime = self._build_runtime(rerun_digest="out-digest")

        checks = runtime.log.of_type(CorrectnessCheckRequestedEvent)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].request_id, "req-1")

        published = runtime.log.of_type(CorrectnessArtifactPublishedEvent)
        self.assertEqual(len(published), 1)
        self.assertEqual(published[0].session_id, checks[0].session_id)

        evaluated = runtime.log.of_type(CorrectnessEvaluatedEvent)
        self.assertEqual(len(evaluated), 1)
        self.assertTrue(evaluated[0].passed)
        self.assertEqual(evaluated[0].session_id, checks[0].session_id)
        self.assertEqual(evaluated[0].request_id, "req-1")

    def test_mismatching_bundle_fails(self) -> None:
        runtime = self._build_runtime(rerun_digest="wrong-digest")

        evaluated = runtime.log.of_type(CorrectnessEvaluatedEvent)
        self.assertEqual(len(evaluated), 1)
        self.assertFalse(evaluated[0].passed)
        self.assertIn("mismatch", evaluated[0].details)


if __name__ == "__main__":
    unittest.main()
