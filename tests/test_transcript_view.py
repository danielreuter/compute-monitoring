from __future__ import annotations

import unittest

from event_log import EventLog, EventView, Principal, TRANSCRIPT_READERS, VERIFICATION_READERS, DISCLOSURE_READERS
from protocols.transparency.correctness import (
    CorrectnessArtifactRef,
    CorrectnessCheckRequestedEvent,
    CorrectnessArtifactPublishedEvent,
    CorrectnessEvaluatedEvent,
    InferenceClaimedEvent,
    ReexecutionBundle,
)
from protocols.transparency.utilization import (
    MachineAddedEvent,
    NetworkObservationEvent,
)
from protocols.compliance import ComplianceEvaluatedEvent
from protocols.disclosure import DisclosurePublishedEvent


class TranscriptViewTest(unittest.TestCase):
    def test_transcript_includes_correct_events(self) -> None:
        log = EventLog(events=[
            InferenceClaimedEvent(
                event_id="claim-1", timestamp=1.0, principal=Principal.PROVER,
                source="prover", readers=TRANSCRIPT_READERS,
                request_id="req-1", model_id="model-a",
                input_digest="in", output_digest="out",
                artifact_ref=CorrectnessArtifactRef(artifact_id="a1"),
            ),
            MachineAddedEvent(
                event_id="machine-1", timestamp=0.0, principal=Principal.PROVER,
                source="prover", readers=TRANSCRIPT_READERS,
                machine_id="m1", machine_kind="gpu",
            ),
            NetworkObservationEvent(
                event_id="net-1", timestamp=2.0, principal=Principal.VERIFIER,
                source="tap", readers=TRANSCRIPT_READERS,
                observation_id="obs-1", data_digest="digest",
            ),
        ])
        transcript = log.transcript()
        self.assertEqual(len(transcript), 3)
        types = {type(e) for e in transcript}
        self.assertEqual(types, {InferenceClaimedEvent, MachineAddedEvent, NetworkObservationEvent})

    def test_transcript_excludes_verification_and_disclosure(self) -> None:
        ref = CorrectnessArtifactRef(artifact_id="a1")
        bundle = ReexecutionBundle(model_id="m", input_bytes=b"", output_digest="d", engine_digest="", metadata={})
        log = EventLog(events=[
            CorrectnessCheckRequestedEvent(
                event_id="check-1", timestamp=1.0, principal=Principal.VERIFIER,
                source="verifier", readers=VERIFICATION_READERS,
                session_id="s1", request_id="req-1",
                artifact_ref=ref, strategy="reexecution",
            ),
            CorrectnessArtifactPublishedEvent(
                event_id="pub-1", timestamp=2.0, principal=Principal.PROVER,
                source="prover", readers=VERIFICATION_READERS,
                session_id="s1", in_reply_to="check-1",
                artifact_ref=ref, bundle=bundle,
            ),
            CorrectnessEvaluatedEvent(
                event_id="eval-1", timestamp=3.0, principal=Principal.VERIFIER,
                source="verifier", readers=VERIFICATION_READERS,
                session_id="s1", request_id="req-1",
                strategy="reexecution", passed=True, details="match",
            ),
            ComplianceEvaluatedEvent(
                event_id="comp-1", timestamp=4.0, principal=Principal.VERIFIER,
                source="compliance", readers=VERIFICATION_READERS,
                passed=True, details="compliant",
            ),
            DisclosurePublishedEvent(
                event_id="disc-1", timestamp=5.0, principal=Principal.VERIFIER,
                source="disclosure", readers=DISCLOSURE_READERS,
                compliant=True, summary="all checks passed",
            ),
        ])
        transcript = log.transcript()
        self.assertEqual(len(transcript), 0)


if __name__ == "__main__":
    unittest.main()
