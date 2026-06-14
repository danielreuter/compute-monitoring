from __future__ import annotations

import unittest

from pocomps import EXTERNAL, NetworkEvent, NetworkEventLog
from pocomps.predictor_inference_request import (
    TASK_PREDICTOR_COMMITMENT,
    DATACENTER_GATEWAY,
    DECODE_SITE,
    MEASUREMENT_PREDICTOR_COMMITMENT,
    PREFILL_SITE,
    PROMPT_COUNT,
    run_epoch,
    run_execution,
    run_setup,
    run_verification,
)


class ExamplePredictorInferenceRequestTest(unittest.TestCase):
    def test_run_epoch(self) -> None:
        setup = run_setup()
        event_log, tasks, error_entropy = run_epoch()

        self.assertEqual(
            [(arrival.send_tick, arrival.prompt) for arrival in setup.prompt_arrivals],
            [
                (1, b"prompt:0:94598e380d7fc4d6"),
                (2, b"prompt:1:81a2cd461f47644d"),
                (3, b"prompt:2:6ba93f239ed129f2"),
                (4, b"prompt:3:48d1ac09ddbe1ab5"),
            ],
        )
        self.assertEqual(len(event_log.events), PROMPT_COUNT * 5)
        self.assertEqual(
            [(event.sender, event.receiver) for event in event_log.events],
            [
                (EXTERNAL, DATACENTER_GATEWAY),
                (DATACENTER_GATEWAY, PREFILL_SITE),
                (EXTERNAL, DATACENTER_GATEWAY),
                (PREFILL_SITE, DECODE_SITE),
                (DATACENTER_GATEWAY, PREFILL_SITE),
                (EXTERNAL, DATACENTER_GATEWAY),
                (DECODE_SITE, DATACENTER_GATEWAY),
                (PREFILL_SITE, DECODE_SITE),
                (DATACENTER_GATEWAY, PREFILL_SITE),
                (EXTERNAL, DATACENTER_GATEWAY),
                (DATACENTER_GATEWAY, EXTERNAL),
                (DECODE_SITE, DATACENTER_GATEWAY),
                (PREFILL_SITE, DECODE_SITE),
                (DATACENTER_GATEWAY, PREFILL_SITE),
                (DATACENTER_GATEWAY, EXTERNAL),
                (DECODE_SITE, DATACENTER_GATEWAY),
                (PREFILL_SITE, DECODE_SITE),
                (DATACENTER_GATEWAY, EXTERNAL),
                (DECODE_SITE, DATACENTER_GATEWAY),
                (DATACENTER_GATEWAY, EXTERNAL),
            ],
        )
        self.assertEqual(
            tuple(task.measurement_ids for task in tasks),
            (
                (1, 3, 6, 10),
                (4, 7, 11, 14),
                (8, 12, 15, 17),
                (13, 16, 18, 19),
            ),
        )
        self.assertEqual(
            sorted(
                measurement_id
                for task in tasks
                for measurement_id in task.measurement_ids
            ),
            [
                event_id
                for event_id, event in enumerate(event_log.events)
                if event.sender != EXTERNAL
            ],
        )
        self.assertEqual(error_entropy, 0)

    def test_predictor_commitments_are_not_storage_blobs(self) -> None:
        setup = run_setup()
        _event_log, storage = run_execution(setup)

        self.assertNotIn(hash(TASK_PREDICTOR_COMMITMENT), storage.blobs)
        self.assertNotIn(hash(MEASUREMENT_PREDICTOR_COMMITMENT), storage.blobs)

    def test_rejects_tampered_monitored_measurement(self) -> None:
        setup = run_setup()
        event_log, storage = run_execution(setup)
        events = list(event_log.events)
        original = events[1]
        tampered_blob = b"tampered"
        events[1] = NetworkEvent(
            sender=original.sender,
            receiver=original.receiver,
            blob_hash=hash(tampered_blob),
            blob_size=len(tampered_blob),
        )

        with self.assertRaisesRegex(AssertionError, "INV-REPLAY-CORRECTNESS"):
            run_verification(setup, NetworkEventLog(tuple(events)), storage)


if __name__ == "__main__":
    unittest.main()
