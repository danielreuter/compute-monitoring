from __future__ import annotations

from dataclasses import replace
import unittest

from pocomps.replay import (
    Baseline,
    Measurement,
    ObjectRef,
    PolicyParams,
    Topology,
    Transfer,
    audit_epoch,
    replay_transfers,
)


PREDICTOR_HASH = hash(b"predictor")


def make_topology() -> Topology:
    return Topology(
        sites={"internet", "gateway", "prefill"},
        links={
            ("internet", "gateway"),
            ("gateway", "prefill"),
        },
        allowed_origins={"internet"},
    )


def make_params(
    *,
    predictor_hash: int = PREDICTOR_HASH,
    advice_budget: int = 10,
    compute_budget: int = 10,
) -> PolicyParams:
    return PolicyParams(
        predictor_hash=predictor_hash,
        advice_budget=advice_budget,
        compute_budget=compute_budget,
    )


def prompt_transfer() -> Transfer:
    return Transfer(
        object_ref=ObjectRef("request:0"),
        src="internet",
        dst="gateway",
        size=12,
        metadata=(("object_commitment", "abc"), ("stage", "user_prompt")),
    )


class PocompReplayTest(unittest.TestCase):
    def test_full_replay_passes(self) -> None:
        topology = make_topology()
        transfer = prompt_transfer()
        observed = replay_transfers((transfer,), topology)

        def predictor(
            _advice: bytes,
            _topology: Topology,
        ) -> tuple[Transfer, ...]:
            return (transfer,)

        result = audit_epoch(
            observed,
            Baseline({PREDICTOR_HASH}),
            topology,
            make_params(),
            b"",
            predictor,
        )

        self.assertEqual(result.measurements, observed)
        self.assertEqual(result.advice_cost, 0)
        self.assertGreaterEqual(result.compute_cost, 0)

    def test_rejects_illegal_custody(self) -> None:
        topology = make_topology()
        transfer = Transfer(
            object_ref=ObjectRef("request:0"),
            src="gateway",
            dst="prefill",
            size=12,
        )

        with self.assertRaisesRegex(AssertionError, "INV-CUSTODY"):
            replay_transfers((transfer,), topology)

    def test_rejects_illegal_topology(self) -> None:
        topology = make_topology()
        transfer = Transfer(
            object_ref=ObjectRef("request:0"),
            src="internet",
            dst="prefill",
            size=12,
        )

        with self.assertRaisesRegex(AssertionError, "INV-TOPOLOGY"):
            replay_transfers((transfer,), topology)

    def test_rejects_uncommitted_predictor(self) -> None:
        def should_not_run(
            _advice: bytes,
            _topology: Topology,
        ) -> tuple[Transfer, ...]:
            raise AssertionError("predictor should not run")

        with self.assertRaisesRegex(AssertionError, "INV-PREDICTOR-COMMITMENT"):
            audit_epoch(
                (),
                Baseline(set()),
                make_topology(),
                make_params(),
                b"",
                should_not_run,
            )

    def test_rejects_advice_over_budget(self) -> None:
        def should_not_run(
            _advice: bytes,
            _topology: Topology,
        ) -> tuple[Transfer, ...]:
            raise AssertionError("predictor should not run")

        with self.assertRaisesRegex(AssertionError, "INV-ADVICE-BUDGET"):
            audit_epoch(
                (),
                Baseline({PREDICTOR_HASH}),
                make_topology(),
                make_params(advice_budget=2),
                b"abc",
                should_not_run,
            )

    def test_rejects_tampered_measurement(self) -> None:
        topology = make_topology()
        transfer = prompt_transfer()
        observed = replay_transfers((transfer,), topology)
        tampered = (replace(observed[0], size=observed[0].size + 1),)

        def predictor(
            _advice: bytes,
            _topology: Topology,
        ) -> tuple[Transfer, ...]:
            return (transfer,)

        with self.assertRaisesRegex(AssertionError, "INV-REPLAY-CORRECTNESS"):
            audit_epoch(
                tampered,
                Baseline({PREDICTOR_HASH}),
                topology,
                make_params(),
                b"",
                predictor,
            )

    def test_rejects_predictor_measurement_output(self) -> None:
        measurement = Measurement(
            hook_id="transfer",
            ordinal=0,
            object_ref=ObjectRef("request:0"),
            src="internet",
            dst="gateway",
            size=12,
        )

        def bad_predictor(
            _advice: bytes,
            _topology: Topology,
        ) -> tuple[Measurement, ...]:
            return (measurement,)

        with self.assertRaisesRegex(AssertionError, "INV-PREDICTOR-OUTPUT-TYPE"):
            audit_epoch(
                (),
                Baseline({PREDICTOR_HASH}),
                make_topology(),
                make_params(),
                b"",
                bad_predictor,  # type: ignore[arg-type]
            )


if __name__ == "__main__":
    unittest.main()
