"""Tests for the memory filling (proof-of-space) protocol."""

from __future__ import annotations

import unittest

from event_log import EventLog
from protocols.transparency.memory_filling import (
    MemoryAuditEvaluatedEvent,
    MemoryAuditTimedOutEvent,
    MemoryFillingAcceptedEvent,
    MemoryFillingProver,
    MemoryFillingVerifier,
    MemoryFillStoppedEvent,
)
from runtime.engine import Runtime


class MemoryFillingFlowTest(unittest.TestCase):
    def test_full_audit_cycle_passes(self):
        prover = MemoryFillingProver()
        verifier = MemoryFillingVerifier(
            fill_size_bytes=64,
            audit_count=3,
            audit_interval_ticks=1.0,
            audit_chunk_length=8,
            seed=42,
        )
        runtime = Runtime(log=EventLog(), participants=[prover, verifier])

        # Tick 1: verifier sends fill, prover stores it (accept buffered)
        runtime.tick(delta=1.0)

        # Tick 2: prover emits accept, verifier sends audit 1 (completed during dispatch)
        runtime.tick(delta=1.0)
        accepts = runtime.log.of_type(MemoryFillingAcceptedEvent)
        self.assertEqual(len(accepts), 1)
        self.assertEqual(accepts[0].fill_size_bytes, 64)

        # Tick 3: audit 2
        runtime.tick(delta=1.0)
        # Tick 4: audit 3
        runtime.tick(delta=1.0)

        # All audits should pass
        evals = runtime.log.of_type(MemoryAuditEvaluatedEvent)
        self.assertEqual(len(evals), 3)
        for ev in evals:
            self.assertTrue(ev.passed, f"audit failed: {ev.details}")

        # Tick 5: verifier sees all audits complete, emits stop
        runtime.tick(delta=1.0)

        stops = runtime.log.of_type(MemoryFillStoppedEvent)
        self.assertEqual(len(stops), 1)
        self.assertTrue(stops[0].passed)
        self.assertEqual(stops[0].audits_passed, 3)
        self.assertEqual(stops[0].audits_failed, 0)

    def test_corrupted_data_fails(self):
        prover = MemoryFillingProver()
        verifier = MemoryFillingVerifier(
            fill_size_bytes=64,
            audit_count=1,
            audit_interval_ticks=1.0,
            audit_chunk_length=8,
            seed=42,
        )
        runtime = Runtime(log=EventLog(), participants=[prover, verifier])

        # Tick 1: fill
        runtime.tick(delta=1.0)

        # Corrupt the prover's stored data
        for session_id in prover._held_data:
            prover._held_data[session_id] = b"\x00" * 64

        # Tick 2: audit against corrupted data (evaluated during dispatch)
        runtime.tick(delta=1.0)

        evals = runtime.log.of_type(MemoryAuditEvaluatedEvent)
        self.assertEqual(len(evals), 1)
        self.assertFalse(evals[0].passed)

        # Tick 3: verifier sees audit complete, emits stop
        runtime.tick(delta=1.0)

        stops = runtime.log.of_type(MemoryFillStoppedEvent)
        self.assertEqual(len(stops), 1)
        self.assertFalse(stops[0].passed)
        self.assertEqual(stops[0].audits_failed, 1)

    def test_audit_timeout(self):
        """Prover that doesn't respond to audits triggers timeout."""

        class SilentProver(MemoryFillingProver):
            """A prover that accepts fills but ignores audit requests."""

            def _handle_audit(self, event, runtime):
                return []

        prover = SilentProver()
        verifier = MemoryFillingVerifier(
            fill_size_bytes=32,
            audit_count=1,
            audit_interval_ticks=1.0,
            timeout_ticks=2.0,
            seed=42,
        )
        runtime = Runtime(log=EventLog(), participants=[prover, verifier])

        # Tick 1: fill
        runtime.tick(delta=1.0)
        # Tick 2: audit sent, no response
        runtime.tick(delta=1.0)
        # Tick 3: still waiting (1 tick elapsed)
        runtime.tick(delta=1.0)
        # Tick 4: timeout fires (2 ticks elapsed since audit)
        runtime.tick(delta=1.0)

        timeouts = runtime.log.of_type(MemoryAuditTimedOutEvent)
        self.assertEqual(len(timeouts), 1)

        # Tick 5: verifier sees audit complete (timed out), emits stop
        runtime.tick(delta=1.0)

        stops = runtime.log.of_type(MemoryFillStoppedEvent)
        self.assertEqual(len(stops), 1)
        self.assertFalse(stops[0].passed)

    def test_stop_frees_memory(self):
        prover = MemoryFillingProver()
        verifier = MemoryFillingVerifier(
            fill_size_bytes=64,
            audit_count=1,
            audit_interval_ticks=1.0,
            audit_chunk_length=8,
            seed=42,
        )
        runtime = Runtime(log=EventLog(), participants=[prover, verifier])

        # Tick 1: fill
        runtime.tick(delta=1.0)
        self.assertEqual(len(prover._held_data), 1)

        # Tick 2: audit completes
        runtime.tick(delta=1.0)

        # Tick 3: stop emitted and dispatched, prover frees data
        runtime.tick(delta=1.0)

        self.assertEqual(len(prover._held_data), 0)


if __name__ == "__main__":
    unittest.main()
