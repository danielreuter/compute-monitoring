from __future__ import annotations

from dataclasses import replace
import unittest

from pocomps import Measurement
from pocomps.simple_inference_simulator import (
    METADATA_PREDICTOR_COMMITMENT,
    PAYLOAD_PREDICTOR_COMMITMENT,
    PUBLIC_PROMPTS,
    TransferMetadata,
    compute_advice,
    encode_metadata_advice,
    predict_measurement_metadata,
    run_epoch,
    run_execution,
    run_setup,
    run_verification,
)


class SimpleInferenceSimulatorTest(unittest.TestCase):
    def test_run_epoch_predicts_metadata_and_payloads(self) -> None:
        measurements, audit_result = run_epoch()

        self.assertEqual(
            [
                (
                    measurement.metadata.time,
                    measurement.metadata.source,
                    measurement.metadata.destination,
                    measurement.metadata.stage,
                )
                for measurement in measurements
            ],
            [
                (0, "environment", "orchestrator", "ingress"),
                (1, "orchestrator", "prefill", "prefill_request"),
                (2, "environment", "orchestrator", "ingress"),
                (3, "prefill", "decode", "prefill_state"),
                (3, "orchestrator", "prefill", "prefill_request"),
                (4, "environment", "orchestrator", "ingress"),
                (5, "decode", "orchestrator", "completion"),
                (5, "prefill", "decode", "prefill_state"),
                (5, "orchestrator", "prefill", "prefill_request"),
                (6, "orchestrator", "environment", "response"),
                (7, "decode", "orchestrator", "completion"),
                (7, "prefill", "decode", "prefill_state"),
                (8, "orchestrator", "environment", "response"),
                (9, "decode", "orchestrator", "completion"),
                (10, "orchestrator", "environment", "response"),
            ],
        )
        self.assertEqual(
            audit_result.metadata_prediction.value,
            tuple(measurement.metadata for measurement in measurements),
        )
        self.assertEqual(
            list(audit_result.sampled_measurement_ids),
            list(range(len(measurements))),
        )
        self.assertEqual(
            [hash(prediction.value) for prediction in audit_result.payload_predictions],
            [measurement.payload for measurement in measurements],
        )
        self.assertEqual(
            sum(
                prediction.entropy_cost
                for prediction in audit_result.payload_predictions
            ),
            0,
        )

    def test_metadata_advice_corrects_timing_jitter(self) -> None:
        setup = run_setup()
        measurements, storage = run_execution(setup)

        base_prediction = predict_measurement_metadata(encode_metadata_advice())
        observed_metadata = tuple(measurement.metadata for measurement in measurements)
        self.assertNotEqual(base_prediction, observed_metadata)

        advice = compute_advice(setup, measurements, storage)
        corrected_prediction = predict_measurement_metadata(advice.metadata)
        self.assertEqual(corrected_prediction, observed_metadata)
        self.assertEqual(advice.metadata, "0,2,4|2:1,3:2,4:2")

        self.assertEqual(
            [
                (
                    metadata.time,
                    metadata.source,
                    metadata.destination,
                    metadata.stage,
                )
                for metadata in base_prediction
            ],
            [
                (0, "environment", "orchestrator", "ingress"),
                (1, "orchestrator", "prefill", "prefill_request"),
                (1, "environment", "orchestrator", "ingress"),
                (2, "prefill", "decode", "prefill_state"),
                (2, "orchestrator", "prefill", "prefill_request"),
                (2, "environment", "orchestrator", "ingress"),
                (3, "decode", "orchestrator", "completion"),
                (3, "prefill", "decode", "prefill_state"),
                (3, "orchestrator", "prefill", "prefill_request"),
                (4, "orchestrator", "environment", "response"),
                (4, "decode", "orchestrator", "completion"),
                (4, "prefill", "decode", "prefill_state"),
                (5, "orchestrator", "environment", "response"),
                (5, "decode", "orchestrator", "completion"),
                (6, "orchestrator", "environment", "response"),
            ],
        )
        self.assertEqual(
            [
                (
                    metadata.time,
                    metadata.source,
                    metadata.destination,
                    metadata.stage,
                )
                for metadata in corrected_prediction
            ],
            [
                (0, "environment", "orchestrator", "ingress"),
                (1, "orchestrator", "prefill", "prefill_request"),
                (2, "environment", "orchestrator", "ingress"),
                (3, "prefill", "decode", "prefill_state"),
                (3, "orchestrator", "prefill", "prefill_request"),
                (4, "environment", "orchestrator", "ingress"),
                (5, "decode", "orchestrator", "completion"),
                (5, "prefill", "decode", "prefill_state"),
                (5, "orchestrator", "prefill", "prefill_request"),
                (6, "orchestrator", "environment", "response"),
                (7, "decode", "orchestrator", "completion"),
                (7, "prefill", "decode", "prefill_state"),
                (8, "orchestrator", "environment", "response"),
                (9, "decode", "orchestrator", "completion"),
                (10, "orchestrator", "environment", "response"),
            ],
        )

    def test_metadata_advice_excludes_prompt_contents(self) -> None:
        setup = run_setup()
        measurements, storage = run_execution(setup)
        advice = compute_advice(setup, measurements, storage)

        for prompt in PUBLIC_PROMPTS:
            self.assertNotIn(prompt.decode(), advice.metadata)
            self.assertNotIn(prompt.hex(), advice.metadata)
        self.assertLessEqual(
            len(advice.metadata),
            setup.params.metadata_entropy_budget_per_epoch,
        )

    def test_predictor_commitments_are_not_storage_objects(self) -> None:
        setup = run_setup()
        _measurements, storage = run_execution(setup)

        self.assertNotIn(hash(METADATA_PREDICTOR_COMMITMENT), storage.objects)
        self.assertNotIn(hash(PAYLOAD_PREDICTOR_COMMITMENT), storage.objects)

    def test_rejects_tampered_stage_metadata(self) -> None:
        setup = run_setup()
        measurements, storage = run_execution(setup)
        tampered = list(measurements)
        metadata = tampered[1].metadata
        self.assertIsInstance(metadata, TransferMetadata)
        tampered[1] = Measurement(
            metadata=replace(metadata, stage="completion"),
            payload=tampered[1].payload,
        )

        with self.assertRaisesRegex(AssertionError, "INV-METADATA-CORRECTNESS"):
            run_verification(setup, tuple(tampered), storage)

    def test_rejects_tampered_destination_metadata(self) -> None:
        setup = run_setup()
        measurements, storage = run_execution(setup)
        tampered = list(measurements)
        metadata = tampered[1].metadata
        self.assertIsInstance(metadata, TransferMetadata)
        tampered[1] = Measurement(
            metadata=replace(metadata, destination="decode"),
            payload=tampered[1].payload,
        )

        with self.assertRaisesRegex(AssertionError, "INV-METADATA-CORRECTNESS"):
            run_verification(setup, tuple(tampered), storage)

    def test_rejects_tampered_payload_hash(self) -> None:
        setup = run_setup()
        measurements, storage = run_execution(setup)
        tampered = list(measurements)
        tampered_object = b"tampered"
        storage.objects[hash(tampered_object)] = tampered_object
        tampered[3] = Measurement(
            metadata=tampered[3].metadata,
            payload=hash(tampered_object),
        )

        with self.assertRaisesRegex(AssertionError, "INV-REPLAY-CORRECTNESS"):
            run_verification(setup, tuple(tampered), storage)


if __name__ == "__main__":
    unittest.main()
