from __future__ import annotations

import unittest

from event_log import EventLog, Principal, TRANSCRIPT_READERS, VERIFICATION_READERS
from protocols.transparency.correctness import (
    CorrectnessArtifactRef,
    CorrectnessEvaluatedEvent,
    InferenceClaimedEvent,
)
from protocols.transparency.utilization import (
    ScheduleCoverageEvaluatedEvent,
    ScheduleCoverageVerifier,
)
from protocols.compliance import ComplianceEvaluatedEvent, ComplianceVerifier
from protocols.disclosure import DisclosurePublishedEvent, DisclosurePublisher
from runtime.engine import Runtime


class ComplianceDisclosureFlowTest(unittest.TestCase):
    def test_passing_transparency_and_approved_model(self) -> None:
        compliance = ComplianceVerifier(approved_models=frozenset({"model-a"}))
        disclosure = DisclosurePublisher()
        schedule = ScheduleCoverageVerifier()
        runtime = Runtime(
            log=EventLog(),
            participants=[schedule, compliance, disclosure],  # type: ignore[list-item]
        )

        # Seed an inference claim with approved model
        runtime.emit(
            InferenceClaimedEvent(
                event_id="claim-1", timestamp=0.0,
                principal=Principal.PROVER, source="prover",
                readers=TRANSCRIPT_READERS,
                request_id="req-1", model_id="model-a",
                input_digest="in", output_digest="out",
                artifact_ref=CorrectnessArtifactRef(artifact_id="a1"),
            )
        )
        runtime.dispatch_until_quiescent()

        # Tick: schedule verifier runs, compliance evaluates, disclosure publishes
        runtime.tick()

        comp_events = runtime.log.of_type(ComplianceEvaluatedEvent)
        self.assertEqual(len(comp_events), 1)
        self.assertTrue(comp_events[0].passed)

        disc_events = runtime.log.of_type(DisclosurePublishedEvent)
        self.assertEqual(len(disc_events), 1)
        self.assertTrue(disc_events[0].compliant)
        self.assertIn("all checks passed", disc_events[0].summary)

    def test_unapproved_model_fails_compliance(self) -> None:
        compliance = ComplianceVerifier(approved_models=frozenset({"model-a"}))
        disclosure = DisclosurePublisher()
        schedule = ScheduleCoverageVerifier()
        runtime = Runtime(
            log=EventLog(),
            participants=[schedule, compliance, disclosure],  # type: ignore[list-item]
        )

        # Seed an inference claim with unapproved model
        runtime.emit(
            InferenceClaimedEvent(
                event_id="claim-1", timestamp=0.0,
                principal=Principal.PROVER, source="prover",
                readers=TRANSCRIPT_READERS,
                request_id="req-1", model_id="model-b",
                input_digest="in", output_digest="out",
                artifact_ref=CorrectnessArtifactRef(artifact_id="a1"),
            )
        )
        runtime.dispatch_until_quiescent()

        runtime.tick()

        comp_events = runtime.log.of_type(ComplianceEvaluatedEvent)
        self.assertEqual(len(comp_events), 1)
        self.assertFalse(comp_events[0].passed)
        self.assertIn("unapproved", comp_events[0].details)

        disc_events = runtime.log.of_type(DisclosurePublishedEvent)
        self.assertEqual(len(disc_events), 1)
        self.assertFalse(disc_events[0].compliant)
        self.assertIn("compliance failed", disc_events[0].summary)


if __name__ == "__main__":
    unittest.main()
