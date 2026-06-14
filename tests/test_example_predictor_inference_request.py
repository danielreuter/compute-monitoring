from __future__ import annotations

import unittest

from pocomps import EXTERNAL, Task
from pocomps.predictor_inference_request import (
    TASK_PREDICTOR_COMMITMENT,
    DATACENTER_GATEWAY,
    MEASUREMENT_PREDICTOR_COMMITMENT,
    POD_GATEWAY,
    audit_inference_request,
    make_epoch,
)


class ExamplePredictorInferenceRequestTest(unittest.TestCase):
    def test_audit_inference_request(self) -> None:
        event_log, tasks, error_entropy = audit_inference_request()

        self.assertEqual(len(event_log.events), 4)
        self.assertEqual(
            [(event.sender, event.receiver) for event in event_log.events],
            [
                (EXTERNAL, DATACENTER_GATEWAY),
                (DATACENTER_GATEWAY, POD_GATEWAY),
                (POD_GATEWAY, DATACENTER_GATEWAY),
                (DATACENTER_GATEWAY, EXTERNAL),
            ],
        )
        self.assertEqual(
            tasks,
            (
                Task(
                    input_hashes=(event_log.events[0].blob_hash,),
                    measurement_ids=(1,),
                ),
                Task(
                    input_hashes=(event_log.events[1].blob_hash,),
                    measurement_ids=(2,),
                ),
                Task(
                    input_hashes=(event_log.events[2].blob_hash,),
                    measurement_ids=(3,),
                ),
            ),
        )
        self.assertEqual(error_entropy, 1)

    def test_predictor_commitments_are_not_storage_blobs(self) -> None:
        _event_log, storage = make_epoch()

        self.assertNotIn(hash(TASK_PREDICTOR_COMMITMENT), storage.blobs)
        self.assertNotIn(hash(MEASUREMENT_PREDICTOR_COMMITMENT), storage.blobs)


if __name__ == "__main__":
    unittest.main()
