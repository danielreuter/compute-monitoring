from __future__ import annotations

import unittest

from event_log import EventLog, Role, TRANSCRIPT_READERS
from protocols.transparency.correctness import (
    CorrectnessArtifactPublishedEvent,
    CorrectnessArtifactRef,
    CorrectnessCheckRequestedEvent,
    CorrectnessEvaluatedEvent,
    CorrectnessVerifier,
    InferenceClaimedEvent,
    ReexecutionBundle,
    ReexecutionStrategy,
)
from runtime.engine import Runtime
from tests._toy_adapters import ToyInferenceAdapter, make_prover


class CorrectnessReexecutionFlowTest(unittest.TestCase):
    def _build_runtime(self, *, rerun_digest: str = "out-digest") -> Runtime:
        inference = ToyInferenceAdapter()
        prover = make_prover(inference=inference)

        # Simulate an inference completing in the adapter
        record = inference.record_inference("req-1", "model-a", b"hello")
        # Override the output digest so we can control match/mismatch
        # (the toy adapter computes its own digest, so we pre-store a bundle
        # with a known digest for the test)
        known_bundle = ReexecutionBundle(
            model_id="model-a",
            input_bytes=b"hello",
            output_digest="out-digest",
            engine_digest="",
            metadata={},
        )
        inference._bundles[record.artifact_ref.artifact_id] = known_bundle
        # Also patch the pending record to use the known digest
        inference._pending.clear()
        inference._pending.append(record)

        strategy = ReexecutionStrategy(rerun=lambda b: rerun_digest)
        verifier = CorrectnessVerifier(strategy=strategy, sample_fraction=1.0)

        runtime = Runtime(
            log=EventLog(),
            participants=[prover, verifier],  # type: ignore[list-item]
        )

        # First tick: prover drains adapter -> InferenceClaimedEvent,
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
