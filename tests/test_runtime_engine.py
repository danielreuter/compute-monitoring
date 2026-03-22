from __future__ import annotations

import unittest
from dataclasses import dataclass, field

from event_log import Event, EventLog, Role, TRANSCRIPT_READERS
from protocols.transparency.utilization import MachineAddedEvent
from runtime.engine import Runtime


@dataclass
class RecordingParticipant:
    writer: Role = Role.VERIFIER
    received: list[Event] = field(default_factory=list)
    tick_count: int = 0
    events_to_emit_on_tick: list[Event] = field(default_factory=list)

    def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
        self.received.append(event)
        return []

    def on_tick(self, runtime: Runtime) -> list[Event]:
        self.tick_count += 1
        result = list(self.events_to_emit_on_tick)
        self.events_to_emit_on_tick = []
        return result


class RuntimeEngineTest(unittest.TestCase):
    def test_events_are_appended_and_delivered_fifo(self) -> None:
        p1 = RecordingParticipant()
        p2 = RecordingParticipant()
        runtime = Runtime(log=EventLog(), participants=[p1, p2])  # type: ignore[list-item]

        e1 = MachineAddedEvent(
            event_id="e1", timestamp=0.0, writer=Role.PROVER, readers=TRANSCRIPT_READERS,
            machine_id="m1", machine_kind="gpu",
        )
        e2 = MachineAddedEvent(
            event_id="e2", timestamp=0.0, writer=Role.PROVER, readers=TRANSCRIPT_READERS,
            machine_id="m2", machine_kind="gpu",
        )
        runtime.emit(e1)
        runtime.emit(e2)
        runtime.dispatch_until_quiescent()

        self.assertEqual(p1.received, [e1, e2])
        self.assertEqual(p2.received, [e1, e2])
        self.assertEqual(runtime.log.events, [e1, e2])

    def test_participants_called_in_registration_order(self) -> None:
        order: list[str] = []

        @dataclass
        class OrderedParticipant:
            writer: Role = Role.VERIFIER
            name: str = ""

            def on_event(self, event: Event, runtime: Runtime) -> list[Event]:
                order.append(self.name)
                return []

            def on_tick(self, runtime: Runtime) -> list[Event]:
                return []

        runtime = Runtime(
            log=EventLog(),
            participants=[
                OrderedParticipant(name="first"),   # type: ignore[list-item]
                OrderedParticipant(name="second"),   # type: ignore[list-item]
                OrderedParticipant(name="third"),    # type: ignore[list-item]
            ],
        )
        runtime.emit(
            MachineAddedEvent(
                event_id="e1", timestamp=0.0, writer=Role.PROVER, readers=TRANSCRIPT_READERS,
                machine_id="m1", machine_kind="gpu",
            )
        )
        runtime.dispatch_until_quiescent()

        self.assertEqual(order, ["first", "second", "third"])

    def test_tick_advances_time_and_drains_to_quiescence(self) -> None:
        p = RecordingParticipant()
        runtime = Runtime(log=EventLog(), participants=[p], now=0.0)  # type: ignore[list-item]

        # Set up an event to be emitted on tick
        e = MachineAddedEvent(
            event_id="tick-event", timestamp=1.0, writer=Role.PROVER, readers=TRANSCRIPT_READERS,
            machine_id="m1", machine_kind="gpu",
        )
        p.events_to_emit_on_tick = [e]

        runtime.tick(delta=1.0)

        self.assertEqual(runtime.now, 1.0)
        self.assertEqual(p.tick_count, 1)
        # The tick-emitted event should have been dispatched
        self.assertIn(e, p.received)
        self.assertIn(e, runtime.log.events)


if __name__ == "__main__":
    unittest.main()
