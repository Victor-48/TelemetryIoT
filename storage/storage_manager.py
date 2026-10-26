import asyncio
from typing import Optional
from gateway.schemas import TelemetryMessage, OSLogMessage, AlertMessage
from storage.database import UnifiedDatabase


class StorageManager:
    """
    Asynchronous Storage Pipeline Worker.
    Consumes validated messages from Gateway queues and updates
    time-series and graph storage asynchronously.
    """
    def __init__(self, db: Optional[UnifiedDatabase] = None):
        self.db = db or UnifiedDatabase()
        self.queue: asyncio.Queue = asyncio.Queue()
        self._running = False

    async def enqueue(self, item_type: str, item_data):
        await self.queue.put((item_type, item_data))

    async def worker_loop(self):
        self._running = True
        while self._running:
            try:
                item_type, data = await self.queue.get()
                if item_type == "telemetry":
                    self.db.save_telemetry(data)
                elif item_type == "log":
                    self.db.save_os_log(data)
                elif item_type == "alert":
                    self.db.save_alert(data)
                self.queue.task_done()
            except asyncio.CancelledError:
                break
            except Exception as e:
                print(f"[StorageManager] Error processing queue item: {e}")

    def stop(self):
        self._running = False
