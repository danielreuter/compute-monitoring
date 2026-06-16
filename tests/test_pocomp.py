import unittest

from pocomps import (
    AuditResult,
    Baseline,
    Measurement,
    PolicyParams,
    Storage,
    audit_epoch,
    predict_metadata,
    predict_payload,
)


METADATA_PREDICTOR_HASH = hash(b"metadata-predictor")
PAYLOAD_PREDICTOR_HASH = hash(b"payload-predictor")


def make_params(
    *,
    metadata_predictor_hash: int = METADATA_PREDICTOR_HASH,
    payload_predictor_hash: int = PAYLOAD_PREDICTOR_HASH,
    metadata_entropy_budget_per_epoch: int = 10,
    compute_budget_for_metadata: int = 10,
    entropy_budget_per_payload: int = 10,
    compute_budget_per_payload: int = 10,
    sample_rate_per_measurement: float = 1.0,
) -> PolicyParams:
    return PolicyParams(
        metadata_predictor_hash=metadata_predictor_hash,
        payload_predictor_hash=payload_predictor_hash,
        metadata_entropy_budget_per_epoch=metadata_entropy_budget_per_epoch,
        compute_budget_for_metadata=compute_budget_for_metadata,
        entropy_budget_per_payload=entropy_budget_per_payload,
        compute_budget_per_payload=compute_budget_per_payload,
        sample_rate_per_measurement=sample_rate_per_measurement,
    )


def make_measurements(*objects: object) -> tuple[Measurement, ...]:
    return tuple(
        Measurement(metadata=("measurement", measurement_id), payload=hash(payload))
        for measurement_id, payload in enumerate(objects)
    )


def make_storage(*objects: object) -> Storage:
    return Storage({hash(payload): payload for payload in objects})


def committed_baseline() -> Baseline:
    return Baseline({METADATA_PREDICTOR_HASH, PAYLOAD_PREDICTOR_HASH})


class PocompTest(unittest.TestCase):
    def setUp(self) -> None:
        self.params = make_params()
        self.objects = (b"alpha", b"bravo")
        self.measurements = make_measurements(*self.objects)
        self.storage = make_storage(*self.objects)

    def test_predict_metadata_wraps_callable_result_and_costs(self) -> None:
        result = predict_metadata(
            committed_baseline(),
            self.params,
            "abc",
            lambda _advice: tuple(
                measurement.metadata for measurement in self.measurements
            ),
        )

        self.assertEqual(
            result.value,
            tuple(measurement.metadata for measurement in self.measurements),
        )
        self.assertGreaterEqual(result.compute_cost, 0)
        self.assertEqual(result.entropy_cost, 3)

    def test_rejects_uncommitted_metadata_predictor_hash(self) -> None:
        def should_not_run(_metadata_advice: str) -> tuple[object, ...]:
            raise AssertionError("predictor should not run")

        with self.assertRaisesRegex(AssertionError, "INV-PREDICTOR-COMMITMENT"):
            predict_metadata(
                Baseline(set()),
                self.params,
                "",
                should_not_run,
            )

    def test_rejects_non_tuple_metadata_prediction(self) -> None:
        with self.assertRaisesRegex(AssertionError, "INV-PREDICTOR-OUTPUT-TYPE"):
            predict_metadata(
                committed_baseline(),
                self.params,
                "",
                lambda _advice: list(
                    measurement.metadata for measurement in self.measurements
                ),  # type: ignore[return-value]
            )

    def test_rejects_metadata_mismatch(self) -> None:
        with self.assertRaisesRegex(AssertionError, "INV-METADATA-CORRECTNESS"):
            audit_epoch(
                self.measurements,
                self.storage,
                committed_baseline(),
                self.params,
                beacon=b"public randomness",
                metadata_advice="",
                payload_advice=("", ""),
                predict_measurement_metadata=lambda _advice: (("wrong", 0),),
                predict_measurement_payload=lambda *_args: b"unused",
            )

    def test_predict_payload_wraps_one_measurement_result_and_costs(self) -> None:
        prediction = predict_payload(
            committed_baseline(),
            self.params,
            1,
            self.measurements[1].metadata,
            "metadata",
            "payload",
            lambda measurement_id, _metadata, _metadata_advice, _payload_advice: (
                self.objects[measurement_id]
            ),
        )

        self.assertEqual(prediction.value, self.objects[1])
        self.assertGreaterEqual(prediction.compute_cost, 0)
        self.assertEqual(prediction.entropy_cost, len("payload"))

    def test_predict_payload_returns_predicted_object(self) -> None:
        prediction = predict_payload(
            committed_baseline(),
            self.params,
            1,
            self.measurements[1].metadata,
            "metadata",
            "payload",
            lambda *_args: b"wrong",
        )

        self.assertEqual(prediction.value, b"wrong")
        self.assertGreaterEqual(prediction.compute_cost, 0)
        self.assertEqual(prediction.entropy_cost, len("payload"))

    def test_rejects_uncommitted_payload_predictor_hash(self) -> None:
        with self.assertRaisesRegex(AssertionError, "INV-PREDICTOR-COMMITMENT"):
            predict_payload(
                Baseline({METADATA_PREDICTOR_HASH}),
                self.params,
                0,
                self.measurements[0].metadata,
                "",
                "",
                lambda *_args: b"unused",
            )

    def test_rejects_payload_mismatch(self) -> None:
        with self.assertRaisesRegex(AssertionError, "INV-REPLAY-CORRECTNESS"):
            audit_epoch(
                self.measurements,
                self.storage,
                committed_baseline(),
                self.params,
                beacon=b"public randomness",
                metadata_advice="",
                payload_advice=("", ""),
                predict_measurement_metadata=lambda _advice: tuple(
                    measurement.metadata for measurement in self.measurements
                ),
                predict_measurement_payload=lambda *_args: b"wrong",
            )

    def test_audit_accounts_each_sampled_payload_prediction(self) -> None:
        result = audit_epoch(
            self.measurements,
            self.storage,
            committed_baseline(),
            self.params,
            beacon=b"public randomness",
            metadata_advice="abc",
            payload_advice=("x", "yz"),
            predict_measurement_metadata=lambda _advice: tuple(
                measurement.metadata for measurement in self.measurements
            ),
            predict_measurement_payload=lambda measurement_id, *_args: self.objects[
                measurement_id
            ],
        )

        self.assertIsInstance(result, AuditResult)
        self.assertEqual(
            result.metadata_prediction.value,
            tuple(measurement.metadata for measurement in self.measurements),
        )
        self.assertEqual(result.metadata_prediction.entropy_cost, 3)
        self.assertGreaterEqual(result.metadata_prediction.compute_cost, 0)
        self.assertEqual(
            list(result.sampled_measurement_ids),
            [0, 1],
        )
        self.assertEqual(
            [prediction.value for prediction in result.payload_predictions],
            list(self.objects),
        )
        self.assertEqual(
            [prediction.entropy_cost for prediction in result.payload_predictions],
            [1, 2],
        )
        self.assertTrue(
            all(
                prediction.compute_cost >= 0
                for prediction in result.payload_predictions
            )
        )

    def test_rejects_metadata_advice_over_budget(self) -> None:
        params = make_params(metadata_entropy_budget_per_epoch=2)

        with self.assertRaisesRegex(AssertionError, "INV-METADATA-ENTROPY"):
            audit_epoch(
                self.measurements,
                self.storage,
                committed_baseline(),
                params,
                beacon=b"public randomness",
                metadata_advice="abc",
                payload_advice=("", ""),
                predict_measurement_metadata=lambda _advice: tuple(
                    measurement.metadata for measurement in self.measurements
                ),
                predict_measurement_payload=lambda measurement_id, *_args: self.objects[
                    measurement_id
                ],
            )

    def test_rejects_payload_advice_over_budget(self) -> None:
        params = make_params(entropy_budget_per_payload=1)

        with self.assertRaisesRegex(AssertionError, "INV-PAYLOAD-ENTROPY"):
            audit_epoch(
                self.measurements,
                self.storage,
                committed_baseline(),
                params,
                beacon=b"public randomness",
                metadata_advice="",
                payload_advice=("", "yz"),
                predict_measurement_metadata=lambda _advice: tuple(
                    measurement.metadata for measurement in self.measurements
                ),
                predict_measurement_payload=lambda measurement_id, *_args: self.objects[
                    measurement_id
                ],
            )

    def test_rejects_payload_advice_shape_mismatch(self) -> None:
        with self.assertRaisesRegex(AssertionError, "INV-ADVICE-SHAPE"):
            audit_epoch(
                self.measurements,
                self.storage,
                committed_baseline(),
                self.params,
                beacon=b"public randomness",
                metadata_advice="",
                payload_advice=("",),
                predict_measurement_metadata=lambda _advice: tuple(
                    measurement.metadata for measurement in self.measurements
                ),
                predict_measurement_payload=lambda measurement_id, *_args: self.objects[
                    measurement_id
                ],
            )

    def test_rejects_bad_sample_rate(self) -> None:
        params = make_params(sample_rate_per_measurement=1.1)

        with self.assertRaisesRegex(AssertionError, "INV-POLICY-PARAMS"):
            audit_epoch(
                self.measurements,
                self.storage,
                committed_baseline(),
                params,
                beacon=b"public randomness",
                metadata_advice="",
                payload_advice=("", ""),
                predict_measurement_metadata=lambda _advice: (),
                predict_measurement_payload=lambda *_args: b"unused",
            )

    def test_rejects_missing_observed_payload_opening(self) -> None:
        with self.assertRaisesRegex(AssertionError, "INV-OBJECT-OPENING"):
            audit_epoch(
                self.measurements,
                Storage({}),
                committed_baseline(),
                self.params,
                beacon=b"public randomness",
                metadata_advice="",
                payload_advice=("", ""),
                predict_measurement_metadata=lambda _advice: tuple(
                    measurement.metadata for measurement in self.measurements
                ),
                predict_measurement_payload=lambda measurement_id, *_args: self.objects[
                    measurement_id
                ],
            )


if __name__ == "__main__":
    unittest.main()
