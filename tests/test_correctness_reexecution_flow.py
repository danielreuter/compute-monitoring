from __future__ import annotations

import unittest

from event_log import EventLog, Principal, TRANSCRIPT_READERS
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
from tests._toy_adapters import make_prover, make_artifact_store


class CorrectnessReexecutionFlowTest(unittest.TestCase):
    def _build_runtime(self, *, rerun_digest: str = "out-digest") -> Runtime:
        store = make_artifact_store()
        prover = make_prover(artifacts=store)

        # Pre-store an artifact
        ref = CorrectnessArtifactRef(artifact_id="artifact-1")
        bundle = ReexecutionBundle(
            model_id="model-a",
            input_bytes=b"hello",
            output_digest="out-digest",
            engine_digest="",
            metadata={},
        )
        store.store(ref, bundle)

        strategy = ReexecutionStrategy(rerun=lambda b: rerun_digest)
        verifier = CorrectnessVerifier(strategy=strategy, sample_fraction=1.0)

        runtime = Runtime(
            log=EventLog(),
            participants=[prover, verifier],  # type: ignore[list-item]
        )

        # Emit a claim
        runtime.emit(
            InferenceClaimedEvent(
                event_id=runtime.make_event_id("inference-claimed"),
                timestamp=0.0,
                principal=Principal.PROVER,
                source="prover",
                readers=TRANSCRIPT_READERS,
                request_id="req-1",
                model_id="model-a",
                input_digest="in-digest",
                output_digest="out-digest",
                artifact_ref=ref,
            )
        )
        runtime.dispatch_until_quiescent()
        return runtime

    def test_matching_bundle_passes(self) -> None:
        runtime = self._build_runtime(rerun_digest="out-digest")

        # Tick triggers verifier to sample, prover to respond, verifier to evaluate
        runtime.tick()

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
        runtime.tick()

        evaluated = runtime.log.of_type(CorrectnessEvaluatedEvent)
        self.assertEqual(len(evaluated), 1)
        self.assertFalse(evaluated[0].passed)
        self.assertIn("mismatch", evaluated[0].details)


if __name__ == "__main__":
    unittest.main()
