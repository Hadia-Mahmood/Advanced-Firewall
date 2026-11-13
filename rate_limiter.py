import time
from collections import defaultdict, deque

class SlidingWindowLimiter:
    def __init__(self, max_packets: int, window_seconds: float = 1.0):
        self.max_packets = max_packets
        self.window = window_seconds
        self._events = defaultdict(deque)  # src_ip -> deque of timestamps

    def allow(self, src_ip: str) -> bool:
        if self.max_packets <= 0:
            return True
        now = time.monotonic()
        dq = self._events[src_ip]
        while dq and dq[0] < now - self.window:
            dq.popleft()
        if len(dq) >= self.max_packets:
            return False
        dq.append(now)
        return True