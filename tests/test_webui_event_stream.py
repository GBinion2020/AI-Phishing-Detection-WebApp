#!/usr/bin/env python3

from __future__ import annotations

import asyncio
import unittest

from webui.event_stream import EventHub


class EventHubTests(unittest.TestCase):
    def test_publish_to_case_subscriber(self) -> None:
        async def _run() -> None:
            hub = EventHub()
            hub.set_loop(asyncio.get_running_loop())

            queue = hub.subscribe("case_a")
            hub.publish("case_a", "stage_started", {"stage": "normalize_envelope"})
            message = await asyncio.wait_for(queue.get(), timeout=0.5)

            self.assertEqual(message["case_id"], "case_a")
            self.assertEqual(message["event"], "stage_started")
            self.assertEqual(message["payload"]["stage"], "normalize_envelope")

            hub.unsubscribe("case_a", queue)

        asyncio.run(_run())


if __name__ == "__main__":
    unittest.main()
