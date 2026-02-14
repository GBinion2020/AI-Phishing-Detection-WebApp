#!/usr/bin/env python3
"""In-memory event hub for case-level SSE fanout."""

from __future__ import annotations

import asyncio
import threading
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class EventHub:
    """Thread-safe pub/sub hub for case execution events."""

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._lock = threading.Lock()
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}

    def set_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        with self._lock:
            self._loop = loop

    def subscribe(self, case_id: str) -> asyncio.Queue[dict[str, Any]]:
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        with self._lock:
            self._subscribers.setdefault(case_id, set()).add(queue)
        return queue

    def unsubscribe(self, case_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
        with self._lock:
            queues = self._subscribers.get(case_id)
            if not queues:
                return
            queues.discard(queue)
            if not queues:
                self._subscribers.pop(case_id, None)

    def publish(self, case_id: str, event: str, payload: dict[str, Any]) -> None:
        with self._lock:
            loop = self._loop
        if loop is None:
            return

        message = {
            "case_id": case_id,
            "event": event,
            "payload": payload,
            "published_at": _now_iso(),
        }
        loop.call_soon_threadsafe(self._fanout_now, case_id, message)

    def _fanout_now(self, case_id: str, message: dict[str, Any]) -> None:
        queues = list(self._subscribers.get(case_id, set()))
        for queue in queues:
            if queue.full():
                try:
                    queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
            try:
                queue.put_nowait(message)
            except asyncio.QueueFull:
                # Drop event under sustained pressure.
                continue
