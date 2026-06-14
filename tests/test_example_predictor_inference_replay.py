from __future__ import annotations

from dataclasses import replace
import unittest

from pocomps.predictor_inference_replay import (
    DATACENTER_GATEWAY,
    DECODE_SITE,
    INTERNET,
    PREFILL_SITE,
    PROMPT_COUNT,
    run_epoch,
    run_execution,
    run_setup,
    run_verification,
)


class ExamplePredictorInferenceReplayTest(unittest.TestCase):
    def test_run_epoch_reconstructs_full_transcript(self) -> None:
        setup = run_setup()
        observed = run_execution(setup)
        verified = run_epoch()

        self.assertEqual(
            [(arrival.send_tick, arrival.prompt) for arrival in setup.prompt_arrivals],
            [
                (1, b"prompt:0:94598e380d7fc4d6"),
                (2, b"prompt:1:81a2cd461f47644d"),
                (3, b"prompt:2:6ba93f239ed129f2"),
                (4, b"prompt:3:48d1ac09ddbe1ab5"),
            ],
        )
        self.assertEqual(len(observed), PROMPT_COUNT * 5)
        self.assertEqual(verified, observed)

    def test_full_route_sequence_is_deterministic(self) -> None:
        setup = run_setup()
        observed = run_execution(setup)

        self.assertEqual(
            [(measurement.src, measurement.dst) for measurement in observed],
            [
                (INTERNET, DATACENTER_GATEWAY),
                (DATACENTER_GATEWAY, PREFILL_SITE),
                (INTERNET, DATACENTER_GATEWAY),
                (PREFILL_SITE, DECODE_SITE),
                (DATACENTER_GATEWAY, PREFILL_SITE),
                (INTERNET, DATACENTER_GATEWAY),
                (DECODE_SITE, DATACENTER_GATEWAY),
                (PREFILL_SITE, DECODE_SITE),
                (DATACENTER_GATEWAY, PREFILL_SITE),
                (INTERNET, DATACENTER_GATEWAY),
                (DATACENTER_GATEWAY, INTERNET),
                (DECODE_SITE, DATACENTER_GATEWAY),
                (PREFILL_SITE, DECODE_SITE),
                (DATACENTER_GATEWAY, PREFILL_SITE),
                (DATACENTER_GATEWAY, INTERNET),
                (DECODE_SITE, DATACENTER_GATEWAY),
                (PREFILL_SITE, DECODE_SITE),
                (DATACENTER_GATEWAY, INTERNET),
                (DECODE_SITE, DATACENTER_GATEWAY),
                (DATACENTER_GATEWAY, INTERNET),
            ],
        )
        self.assertEqual(
            [dict(measurement.metadata)["stage"] for measurement in observed],
            [
                "user_prompt",
                "prefill_request",
                "user_prompt",
                "prefill_state",
                "prefill_request",
                "user_prompt",
                "completion",
                "prefill_state",
                "prefill_request",
                "user_prompt",
                "response",
                "completion",
                "prefill_state",
                "prefill_request",
                "response",
                "completion",
                "prefill_state",
                "response",
                "completion",
                "response",
            ],
        )

    def test_rejects_tampered_measurement(self) -> None:
        setup = run_setup()
        observed = run_execution(setup)
        tampered = list(observed)
        tampered[1] = replace(
            tampered[1],
            object_commitment="tampered",
        )

        with self.assertRaisesRegex(AssertionError, "INV-REPLAY-CORRECTNESS"):
            run_verification(setup, tuple(tampered))


if __name__ == "__main__":
    unittest.main()
