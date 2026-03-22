from __future__ import annotations

import unittest

from event_log import EventLog
from protocols.transparency.correctness import (
    CorrectnessCheckRequestedEvent,
    CorrectnessEvaluatedEvent,
    ZeroKnowledgeProofSubmittedEvent,
    ZeroKnowledgeProver,
    ZeroKnowledgeVerifier,
)
from runtime.engine import Runtime


class ZeroKnowledgeCorrectnessFlowTest(unittest.TestCase):
    def test_matching_proof_passes(self) -> None:
        prover = ZeroKnowledgeProver()
        prover.report_inference("req-1", "model-a", b"hello")

        verifier = ZeroKnowledgeVerifier(
            verify_proof=lambda bundle: (bundle.proof_system == "dummy-zkvm", "proof verified"),
            sample_fraction=1.0,
        )
        runtime = Runtime(
            log=EventLog(),
            participants=[prover, verifier],  # type: ignore[list-item]
        )

        runtime.tick()

        checks = runtime.log.of_type(CorrectnessCheckRequestedEvent)
        self.assertEqual(len(checks), 1)
        self.assertEqual(checks[0].mechanism, "zero_knowledge")

        proofs = runtime.log.of_type(ZeroKnowledgeProofSubmittedEvent)
        self.assertEqual(len(proofs), 1)
        self.assertEqual(proofs[0].session_id, checks[0].session_id)

        evaluated = runtime.log.of_type(CorrectnessEvaluatedEvent)
        self.assertEqual(len(evaluated), 1)
        self.assertTrue(evaluated[0].passed)
        self.assertEqual(evaluated[0].mechanism, "zero_knowledge")
        self.assertEqual(evaluated[0].details, "proof verified")


if __name__ == "__main__":
    unittest.main()
