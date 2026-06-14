import unittest

from pocomp import (
    Storage,
    Claim,
    NetworkEvent,
    NetworkEventLog,
    PolicyParams,
    audit_epoch,
    predict_claims,
    predict_measurements,
)


class EmptyBaseline:
    def contains(self, blob_hash: int) -> bool:
        return False


class SetBaseline:
    def __init__(self, blob_hashes: set[int]) -> None:
        self.blob_hashes = blob_hashes

    def contains(self, blob_hash: int) -> bool:
        return blob_hash in self.blob_hashes


class PocompClaimsTest(unittest.TestCase):
    def setUp(self) -> None:
        self.params = PolicyParams(
            claim_predictor_hash=0,
            measurement_predictor_hash=0,
            compute_budget_for_claims=10,
            compute_budget_per_claim=10,
            error_entropy_budget_per_epoch=10,
            entropy_budget_per_claim=10,
            sample_rate_per_output_byte=0,
        )
        self.baseline = EmptyBaseline()
        self.storage = Storage({})

    def test_rejects_invalid_output_event_id_before_lookup(self) -> None:
        program = b"""
COMPUTE_COST = 1


def main(_event_log, _advice):
    from pocomp import Claim

    return (Claim(input_hashes=(), measurement_ids=(1,)),)
"""
        output = NetworkEvent(sender=1, receiver=2, blob_hash=101, blob_size=1)
        event_log = NetworkEventLog((output,))
        storage = Storage({hash(program): program})
        params = PolicyParams(
            claim_predictor_hash=hash(program),
            measurement_predictor_hash=0,
            compute_budget_for_claims=10,
            compute_budget_per_claim=10,
            error_entropy_budget_per_epoch=10,
            entropy_budget_per_claim=10,
            sample_rate_per_output_byte=0,
        )

        with self.assertRaisesRegex(AssertionError, "INV-OUTPUT-VALIDITY"):
            predict_claims(
                event_log,
                storage,
                SetBaseline({hash(program)}),
                params,
                "",
            )

    def test_rejects_uncommitted_claim_predictor_program(self) -> None:
        program = b"claim predictor"
        storage = Storage({hash(program): program})
        params = PolicyParams(
            claim_predictor_hash=hash(program),
            measurement_predictor_hash=0,
            compute_budget_for_claims=10,
            compute_budget_per_claim=10,
            error_entropy_budget_per_epoch=10,
            entropy_budget_per_claim=10,
            sample_rate_per_output_byte=0,
        )

        with self.assertRaisesRegex(AssertionError, "INV-PREDICTOR-COMMITMENT"):
            predict_claims(
                NetworkEventLog(()),
                storage,
                self.baseline,
                params,
                "",
            )

    def test_predict_claims_opens_committed_program_bytes(self) -> None:
        program = b"""
COMPUTE_COST = 3


def main(_event_log, _advice):
    return ()
"""
        storage = Storage({hash(program): program})
        params = PolicyParams(
            claim_predictor_hash=hash(program),
            measurement_predictor_hash=0,
            compute_budget_for_claims=10,
            compute_budget_per_claim=10,
            error_entropy_budget_per_epoch=10,
            entropy_budget_per_claim=10,
            sample_rate_per_output_byte=0,
        )

        claims_result = predict_claims(
            NetworkEventLog(()),
            storage,
            SetBaseline({hash(program)}),
            params,
            "101",
        )

        self.assertEqual(claims_result.value, ())
        self.assertEqual(claims_result.compute_cost, 3)
        self.assertEqual(claims_result.entropy_cost, 3)

    def test_predict_claims_rejects_uncommitted_claim_input_hash(self) -> None:
        input_blob = b"input"
        output_blob = b"output"
        program = f"""
COMPUTE_COST = 1
INPUT_HASH = {hash(input_blob)}


def main(_event_log, _advice):
    from pocomp import Claim

    return (Claim(input_hashes=(INPUT_HASH,), measurement_ids=(0,)),)
""".encode()
        storage = Storage({hash(program): program})
        event_log = NetworkEventLog(
            (
                NetworkEvent(
                    sender=1,
                    receiver=2,
                    blob_hash=hash(output_blob),
                    blob_size=len(output_blob),
                ),
            )
        )
        params = PolicyParams(
            claim_predictor_hash=hash(program),
            measurement_predictor_hash=0,
            compute_budget_for_claims=10,
            compute_budget_per_claim=10,
            error_entropy_budget_per_epoch=10,
            entropy_budget_per_claim=10,
            sample_rate_per_output_byte=0,
        )

        with self.assertRaisesRegex(AssertionError, "INV-INPUT-VALIDITY"):
            predict_claims(
                event_log,
                storage,
                SetBaseline({hash(program)}),
                params,
                "",
            )

    def test_claim_prediction_draws_from_epoch_error_entropy_budget(self) -> None:
        program = b"""
COMPUTE_COST = 1


def main(_event_log, _advice):
    return ()
"""
        storage = Storage({hash(program): program})
        params = PolicyParams(
            claim_predictor_hash=hash(program),
            measurement_predictor_hash=0,
            compute_budget_for_claims=10,
            compute_budget_per_claim=10,
            error_entropy_budget_per_epoch=2,
            entropy_budget_per_claim=10,
            sample_rate_per_output_byte=0,
        )

        with self.assertRaisesRegex(AssertionError, "INV-EPOCH-ERROR-ENTROPY"):
            audit_epoch(
                NetworkEventLog(()),
                storage,
                SetBaseline({hash(program)}),
                params,
                beacon=b"public randomness",
                claim_advice="101",
                measurement_advice="",
            )

    def test_rejects_measurement_prediction_over_claim_entropy_budget(self) -> None:
        claim_program = b"""
COMPUTE_COST = 1


def main(event_log, _advice):
    from pocomp import Claim

    input_event, _output_event = event_log.events
    return (Claim(input_hashes=(input_event.blob_hash,), measurement_ids=(1,)),)
"""
        measurement_program = b"""
COMPUTE_COST = 1


def main(_claim, _inputs, _advice):
    return (b"output",)
"""
        input_blob = b"input"
        output_blob = b"output"
        storage = Storage(
            {
                hash(claim_program): claim_program,
                hash(measurement_program): measurement_program,
                hash(input_blob): input_blob,
                hash(output_blob): output_blob,
            }
        )
        event_log = NetworkEventLog(
            (
                NetworkEvent(
                    sender=-1,
                    receiver=1,
                    blob_hash=hash(input_blob),
                    blob_size=len(input_blob),
                ),
                NetworkEvent(
                    sender=1,
                    receiver=2,
                    blob_hash=hash(output_blob),
                    blob_size=len(output_blob),
                ),
            )
        )
        params = PolicyParams(
            claim_predictor_hash=hash(claim_program),
            measurement_predictor_hash=hash(measurement_program),
            compute_budget_for_claims=10,
            compute_budget_per_claim=10,
            error_entropy_budget_per_epoch=10,
            entropy_budget_per_claim=1,
            sample_rate_per_output_byte=1.0,
        )

        with self.assertRaisesRegex(AssertionError, "INV-REPLAY-ENTROPY"):
            audit_epoch(
                event_log,
                storage,
                SetBaseline(
                    {
                        hash(claim_program),
                        hash(measurement_program),
                        hash(input_blob),
                    }
                ),
                params,
                beacon=b"public randomness",
                claim_advice="",
                measurement_advice="10",
            )

    def test_predict_measurements_opens_claim_input_hashes(self) -> None:
        program = b"""
COMPUTE_COST = 4


def main(_claim, inputs, _advice):
    return inputs
"""
        input_blob = b"input"
        event_log = NetworkEventLog(
            (
                NetworkEvent(
                    sender=1,
                    receiver=2,
                    blob_hash=hash(input_blob),
                    blob_size=len(input_blob),
                ),
            )
        )
        storage = Storage(
            {
                hash(program): program,
                hash(input_blob): input_blob,
            }
        )
        params = PolicyParams(
            claim_predictor_hash=0,
            measurement_predictor_hash=hash(program),
            compute_budget_for_claims=10,
            compute_budget_per_claim=10,
            error_entropy_budget_per_epoch=10,
            entropy_budget_per_claim=10,
            sample_rate_per_output_byte=0,
        )

        measurements_result = predict_measurements(
            Claim(input_hashes=(hash(input_blob),), measurement_ids=(0,)),
            event_log,
            storage,
            SetBaseline({hash(program), hash(input_blob)}),
            params,
            "",
        )

        self.assertEqual(measurements_result.value, (input_blob,))
        self.assertEqual(measurements_result.compute_cost, 4)

    def test_rejects_uncommitted_claim_input_hash(self) -> None:
        program = b"""
COMPUTE_COST = 1


def main(_claim, inputs, _advice):
    return inputs
"""
        input_blob = b"input"
        event_log = NetworkEventLog(
            (
                NetworkEvent(
                    sender=1,
                    receiver=2,
                    blob_hash=hash(input_blob),
                    blob_size=len(input_blob),
                ),
            )
        )
        storage = Storage(
            {
                hash(program): program,
                hash(input_blob): input_blob,
            }
        )
        params = PolicyParams(
            claim_predictor_hash=0,
            measurement_predictor_hash=hash(program),
            compute_budget_for_claims=10,
            compute_budget_per_claim=10,
            error_entropy_budget_per_epoch=10,
            entropy_budget_per_claim=10,
            sample_rate_per_output_byte=0,
        )

        with self.assertRaisesRegex(AssertionError, "INV-INPUT-VALIDITY"):
            predict_measurements(
                Claim(input_hashes=(hash(input_blob),), measurement_ids=(0,)),
                event_log,
                storage,
                SetBaseline({hash(program)}),
                params,
                "",
            )

    def test_rejects_missing_input_hash(self) -> None:
        program = b"""
COMPUTE_COST = 1


def main(_claim, _inputs, _advice):
    return ()
"""
        missing_input_hash = hash(b"missing")
        event_log = NetworkEventLog(
            (
                NetworkEvent(
                    sender=1,
                    receiver=2,
                    blob_hash=missing_input_hash,
                    blob_size=7,
                ),
            )
        )
        storage = Storage({hash(program): program})
        params = PolicyParams(
            claim_predictor_hash=0,
            measurement_predictor_hash=hash(program),
            compute_budget_for_claims=10,
            compute_budget_per_claim=10,
            error_entropy_budget_per_epoch=10,
            entropy_budget_per_claim=10,
            sample_rate_per_output_byte=0,
        )

        with self.assertRaisesRegex(AssertionError, "INV-INPUT-VALIDITY"):
            predict_measurements(
                Claim(input_hashes=(missing_input_hash,), measurement_ids=(0,)),
                event_log,
                storage,
                SetBaseline({hash(program), missing_input_hash}),
                params,
                "",
            )

    def test_rejects_duplicate_output_event_ids(self) -> None:
        program = b"""
COMPUTE_COST = 1


def main(_event_log, _advice):
    from pocomp import Claim

    return (
        Claim(input_hashes=(), measurement_ids=(0,)),
        Claim(input_hashes=(), measurement_ids=(0,)),
    )
"""
        output = NetworkEvent(sender=1, receiver=2, blob_hash=101, blob_size=1)
        event_log = NetworkEventLog((output,))
        storage = Storage({hash(program): program})
        params = PolicyParams(
            claim_predictor_hash=hash(program),
            measurement_predictor_hash=0,
            compute_budget_for_claims=10,
            compute_budget_per_claim=10,
            error_entropy_budget_per_epoch=10,
            entropy_budget_per_claim=10,
            sample_rate_per_output_byte=0,
        )

        with self.assertRaisesRegex(AssertionError, "INV-OUTPUT-OWNERSHIP"):
            predict_claims(
                event_log,
                storage,
                SetBaseline({hash(program)}),
                params,
                "",
            )


if __name__ == "__main__":
    unittest.main()
