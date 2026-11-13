"""
Observe real local TCP connection tables and flag bursts of newly observed
remote endpoints. This is connection-rate monitoring, not HTTP request
inspection and not proof of a DDoS attack.
"""

import os
import time
import threading
import logging
from collections import deque, defaultdict
from datetime import datetime

try:
    import psutil
except ImportError:
    psutil = None


class TrafficMonitor(threading.Thread):
    def __init__(
        self,
        log_dir="logs",
        poll_interval=1.0,
        window_seconds=10.0,
        threshold=20,
        auto_block=False,
    ):
        super().__init__(daemon=True)
        self.poll_interval = max(0.25, float(poll_interval))
        self.window_seconds = max(2.0, float(window_seconds))
        self.threshold = max(2, int(threshold))
        self.auto_block = bool(auto_block)
        self._stop_event = threading.Event()
        self._events = defaultdict(deque)
        self._alerted = set()
        self._last_seen = set()
        self._status = "Not started"

        os.makedirs(log_dir, exist_ok=True)
        self.logger = logging.getLogger("NetGuardPro")
        self.logger.setLevel(logging.INFO)
        if not self.logger.handlers:
            handler = logging.FileHandler(
                os.path.join(log_dir, "security.log"), encoding="utf-8"
            )
            handler.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s"
            ))
            self.logger.addHandler(handler)

    def stop(self):
        self._stop_event.set()

    def status(self):
        return (
            f"Traffic monitor: {self._status}\n"
            f"Polling interval: {self.poll_interval}s | "
            f"Threshold: >{self.threshold} new remote endpoints in "
            f"{self.window_seconds:g}s\n"
            f"Automatic firewall blocking: {'ON' if self.auto_block else 'OFF'}"
        )

    @staticmethod
    def _remote_ip(connection):
        address = connection.raddr
        if not address:
            return None
        return getattr(address, "ip", address[0])

    def run(self):
        if psutil is None:
            self._status = "Unavailable: install dependencies with pip install -r requirements.txt"
            self.logger.error(self._status)
            return

        self._status = "Running"
        self.logger.info("Traffic monitor started.")
        print("[+] Real TCP connection-table monitoring started.")

        while not self._stop_event.is_set():
            now = time.monotonic()
            try:
                current = set()
                connections = psutil.net_connections(kind="tcp")

                for conn in connections:
                    if conn.status != psutil.CONN_ESTABLISHED:
                        continue
                    ip = self._remote_ip(conn)
                    if not ip:
                        continue
                    # Count a newly observed (remote IP, remote port, local port)
                    # tuple once; repeated polling of the same connection is not
                    # counted as a new event.
                    local_port = getattr(conn.laddr, "port", None)
                    remote_port = getattr(conn.raddr, "port", None)
                    key = (ip, remote_port, local_port)
                    current.add(key)

                new_keys = current - self._last_seen
                for key in new_keys:
                    ip = key[0]
                    self._events[ip].append(now)

                self._last_seen = current

                for ip, events in list(self._events.items()):
                    while events and now - events[0] > self.window_seconds:
                        events.popleft()

                    if len(events) > self.threshold and ip not in self._alerted:
                        message = (
                            f"High connection burst observed from {ip}: "
                            f"{len(events)} new TCP endpoints in "
                            f"{self.window_seconds:g}s."
                        )
                        print(f"[!] ALERT: {message}")
                        self.logger.warning(message)
                        self._alerted.add(ip)

                        if self.auto_block:
                            # Automatic blocking is intentionally opt-in.
                            from firewall import block_ip
                            result = block_ip(ip)
                            self.logger.info(
                                "Auto-block %s: %s", ip, result.message
                            )
                            print(f"[*] Auto-block result for {ip}: {result.message}")

                    if not events:
                        self._events.pop(ip, None)
                        self._alerted.discard(ip)

            except (psutil.AccessDenied, OSError) as exc:
                self._status = f"Limited permissions / monitoring error: {exc}"
                self.logger.warning(self._status)
            except Exception as exc:
                self.logger.exception("Unexpected monitoring error: %s", exc)

            self._stop_event.wait(self.poll_interval)

        self._status = "Stopped"
        self.logger.info("Traffic monitor stopped.")
