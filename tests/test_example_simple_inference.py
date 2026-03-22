from __future__ import annotations

import unittest

from event_log import EventView
from examples.simple_inference import run_example
from protocols.transparency.correctness import (
    CorrectnessEvaluatedEvent,
    InferenceClaimedEvent,
)
from protocols.transparency.utilization import (
    MachineAddedEvent,
    ScheduleCoverageEvaluatedEvent,
    WorkloadStartedEvent,
)
from protocols.transparency.remote_attestation import (
    RemoteAttestationClaimedEvent,
    RemoteAttestationEvaluatedEvent,
)
from protocols.compliance import ComplianceEvaluatedEvent
from protocols.disclosure import DisclosurePublishedEvent


class ExampleSimpleInferenceTest(unittest.TestCase):
    def test_end_to_end_without_transport(self) -> None:
        runtime = run_example()
        log = runtime.log

        # Transcript events present
        self.assertTrue(len(log.of_type(MachineAddedEvent)) >= 1)
        self.assertTrue(len(log.of_type(WorkloadStartedEvent)) >= 1)
        self.assertTrue(len(log.of_type(InferenceClaimedEvent)) >= 1)
        self.assertTrue(len(log.of_type(RemoteAttestationClaimedEvent)) >= 1)

        # Verification events present
        self.assertTrue(len(log.of_type(CorrectnessEvaluatedEvent)) >= 1)
        self.assertTrue(len(log.of_type(ScheduleCoverageEvaluatedEvent)) >= 1)
        self.assertTrue(len(log.of_type(RemoteAttestationEvaluatedEvent)) >= 1)

        # Compliance and disclosure
        comp = log.of_type(ComplianceEvaluatedEvent)
        self.assertEqual(len(comp), 1)
        self.assertTrue(comp[0].passed)

        disc = log.of_type(DisclosurePublishedEvent)
        self.assertEqual(len(disc), 1)
        self.assertTrue(disc[0].compliant)

        # Transcript view is clean
        transcript = log.transcript()
        for event in transcript:
            self.assertIn(EventView.TRANSCRIPT, type(event).views)
        self.assertFalse(any(isinstance(e, ComplianceEvaluatedEvent) for e in transcript))
        self.assertFalse(any(isinstance(e, DisclosurePublishedEvent) for e in transcript))


if __name__ == "__main__":
    unittest.main()
