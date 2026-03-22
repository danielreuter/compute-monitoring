from __future__ import annotations

import unittest

from event_log import EventLog, Side, VERIFICATION_READERS
from protocols.transparency.utilization import (
    EngineStopAcknowledgedEvent,
    EngineStopRequestedEvent,
    UtilizationProver,
)
from runtime.engine import Runtime


class UtilizationControlFlowTest(unittest.TestCase):
    def test_engine_stop_flow(self) -> None:
        prover = UtilizationProver()
        runtime = Runtime(
            log=EventLog(),
            participants=[prover],  # type: ignore[list-item]
        )

        runtime.emit(
            EngineStopRequestedEvent(
                event_id="stop-1", timestamp=0.0,
                writer=Side.VERIFIER, readers=VERIFICATION_READERS,
                session_id="session-1", reason="test stop",
            )
        )
        runtime.dispatch_until_quiescent()

        acks = runtime.log.of_type(EngineStopAcknowledgedEvent)
        self.assertEqual(len(acks), 1)
        self.assertEqual(acks[0].session_id, "session-1")
        self.assertTrue(acks[0].succeeded)
        self.assertEqual(acks[0].details, "engine stopped")


if __name__ == "__main__":
    unittest.main()
