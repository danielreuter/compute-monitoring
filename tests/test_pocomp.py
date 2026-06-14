import unittest

from pocomps import (
    Baseline,
    Task,
    NetworkEvent,
    NetworkEventLog,
    PolicyParams,
    Storage,
    audit_epoch,
    predict_tasks,
    predict_measurements,
)


TASK_PREDICTOR_HASH = hash(b"task-predictor")
MEASUREMENT_PREDICTOR_HASH = hash(b"measurement-predictor")


def make_params(
    *,
    task_predictor_hash: int = TASK_PREDICTOR_HASH,
    measurement_predictor_hash: int = MEASUREMENT_PREDICTOR_HASH,
    compute_budget_for_tasks: int = 10,
    compute_budget_per_task: int = 10,
    error_entropy_budget_per_epoch: int = 10,
    entropy_budget_per_task: int = 10,
    sample_rate_per_output_byte: float = 0,
) -> PolicyParams:
    return PolicyParams(
        task_predictor_hash=task_predictor_hash,
        measurement_predictor_hash=measurement_predictor_hash,
        compute_budget_for_tasks=compute_budget_for_tasks,
        compute_budget_per_task=compute_budget_per_task,
        error_entropy_budget_per_epoch=error_entropy_budget_per_epoch,
        entropy_budget_per_task=entropy_budget_per_task,
        sample_rate_per_output_byte=sample_rate_per_output_byte,
    )


def no_tasks(_event_log: NetworkEventLog, _advice: str) -> tuple[Task, ...]:
    return ()


def no_measurements(
    _task: Task,
    _inputs: tuple[object, ...],
    _advice: str,
) -> tuple[object, ...]:
    return ()


class PocompTasksTest(unittest.TestCase):
    def setUp(self) -> None:
        self.params = make_params()
        self.baseline = Baseline(set())
        self.storage = Storage({})

    def test_rejects_invalid_output_event_id_before_lookup(self) -> None:
        def task_predictor(
            _event_log: NetworkEventLog,
            _advice: str,
        ) -> tuple[Task, ...]:
            return (Task(input_hashes=(), measurement_ids=(1,)),)

        output = NetworkEvent(sender=1, receiver=2, blob_hash=101, blob_size=1)
        event_log = NetworkEventLog((output,))

        with self.assertRaisesRegex(AssertionError, "INV-OUTPUT-VALIDITY"):
            predict_tasks(
                event_log,
                self.storage,
                Baseline({TASK_PREDICTOR_HASH}),
                self.params,
                "",
                task_predictor,
            )

    def test_rejects_uncommitted_task_predictor_hash(self) -> None:
        def should_not_run(
            _event_log: NetworkEventLog,
            _advice: str,
        ) -> tuple[Task, ...]:
            raise AssertionError("predictor should not run")

        with self.assertRaisesRegex(AssertionError, "INV-PREDICTOR-COMMITMENT"):
            predict_tasks(
                NetworkEventLog(()),
                self.storage,
                self.baseline,
                self.params,
                "",
                should_not_run,
            )

    def test_predict_tasks_wraps_callable_result_and_costs(self) -> None:
        tasks_result = predict_tasks(
            NetworkEventLog(()),
            self.storage,
            Baseline({TASK_PREDICTOR_HASH}),
            self.params,
            "101",
            no_tasks,
        )

        self.assertEqual(tasks_result.value, ())
        self.assertGreaterEqual(tasks_result.compute_cost, 0)
        self.assertEqual(tasks_result.entropy_cost, 3)

    def test_predict_tasks_rejects_uncommitted_task_input_hash(self) -> None:
        input_blob = b"input"
        output_blob = b"output"

        def task_predictor(
            _event_log: NetworkEventLog,
            _advice: str,
        ) -> tuple[Task, ...]:
            return (Task(input_hashes=(hash(input_blob),), measurement_ids=(0,)),)

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

        with self.assertRaisesRegex(AssertionError, "INV-INPUT-VALIDITY"):
            predict_tasks(
                event_log,
                self.storage,
                Baseline({TASK_PREDICTOR_HASH}),
                self.params,
                "",
                task_predictor,
            )

    def test_task_prediction_draws_from_epoch_error_entropy_budget(self) -> None:
        params = make_params(error_entropy_budget_per_epoch=2)

        with self.assertRaisesRegex(AssertionError, "INV-EPOCH-ERROR-ENTROPY"):
            audit_epoch(
                NetworkEventLog(()),
                self.storage,
                Baseline({TASK_PREDICTOR_HASH}),
                params,
                beacon=b"public randomness",
                task_advice="101",
                measurement_advice="",
                task_predictor=no_tasks,
                measurement_predictor=no_measurements,
            )

    def test_rejects_measurement_prediction_over_task_entropy_budget(self) -> None:
        input_blob = b"input"
        output_blob = b"output"
        storage = Storage({hash(input_blob): input_blob})
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
        params = make_params(
            entropy_budget_per_task=1,
            sample_rate_per_output_byte=1.0,
        )

        def task_predictor(
            event_log: NetworkEventLog,
            _advice: str,
        ) -> tuple[Task, ...]:
            input_event, _output_event = event_log.events
            return (
                Task(input_hashes=(input_event.blob_hash,), measurement_ids=(1,)),
            )

        def measurement_predictor(
            _task: Task,
            _inputs: tuple[object, ...],
            _advice: str,
        ) -> tuple[object, ...]:
            return (output_blob,)

        with self.assertRaisesRegex(AssertionError, "INV-REPLAY-ENTROPY"):
            audit_epoch(
                event_log,
                storage,
                Baseline(
                    {
                        TASK_PREDICTOR_HASH,
                        MEASUREMENT_PREDICTOR_HASH,
                        hash(input_blob),
                    }
                ),
                params,
                beacon=b"public randomness",
                task_advice="",
                measurement_advice="10",
                task_predictor=task_predictor,
                measurement_predictor=measurement_predictor,
            )

    def test_predict_measurements_opens_task_input_hashes(self) -> None:
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
        storage = Storage({hash(input_blob): input_blob})

        def measurement_predictor(
            _task: Task,
            inputs: tuple[object, ...],
            _advice: str,
        ) -> tuple[object, ...]:
            return inputs

        measurements_result = predict_measurements(
            Task(input_hashes=(hash(input_blob),), measurement_ids=(0,)),
            event_log,
            storage,
            Baseline({MEASUREMENT_PREDICTOR_HASH, hash(input_blob)}),
            self.params,
            "",
            measurement_predictor,
        )

        self.assertEqual(measurements_result.value, (input_blob,))
        self.assertGreaterEqual(measurements_result.compute_cost, 0)

    def test_rejects_uncommitted_task_input_hash(self) -> None:
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
        storage = Storage({hash(input_blob): input_blob})

        with self.assertRaisesRegex(AssertionError, "INV-INPUT-VALIDITY"):
            predict_measurements(
                Task(input_hashes=(hash(input_blob),), measurement_ids=(0,)),
                event_log,
                storage,
                Baseline({MEASUREMENT_PREDICTOR_HASH}),
                self.params,
                "",
                no_measurements,
            )

    def test_rejects_missing_input_hash(self) -> None:
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

        with self.assertRaisesRegex(AssertionError, "INV-INPUT-VALIDITY"):
            predict_measurements(
                Task(input_hashes=(missing_input_hash,), measurement_ids=(0,)),
                event_log,
                self.storage,
                Baseline({MEASUREMENT_PREDICTOR_HASH, missing_input_hash}),
                self.params,
                "",
                no_measurements,
            )

    def test_rejects_duplicate_output_event_ids(self) -> None:
        def task_predictor(
            _event_log: NetworkEventLog,
            _advice: str,
        ) -> tuple[Task, ...]:
            return (
                Task(input_hashes=(), measurement_ids=(0,)),
                Task(input_hashes=(), measurement_ids=(0,)),
            )

        output = NetworkEvent(sender=1, receiver=2, blob_hash=101, blob_size=1)
        event_log = NetworkEventLog((output,))

        with self.assertRaisesRegex(AssertionError, "INV-OUTPUT-OWNERSHIP"):
            predict_tasks(
                event_log,
                self.storage,
                Baseline({TASK_PREDICTOR_HASH}),
                self.params,
                "",
                task_predictor,
            )


if __name__ == "__main__":
    unittest.main()
