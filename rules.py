import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, time
from typing import Optional, List

@dataclass
class Rule:
    action: str                 # ALLOW / DENY / LOG
    proto: str                  # TCP / UDP / ICMP / ANY
    src_cidr: str
    src_port: str               # "ANY", int, or "start-end"
    dst_cidr: str
    dst_port: str
    schedule: Optional[str] = None  # "HH:MM-HH:MM"

    def matches(self, pkt) -> bool:
        if self.proto != "ANY" and self.proto != pkt.proto:
            return False
        if not self._ip_matches(self.src_cidr, pkt.src_ip):
            return False
        if not self._ip_matches(self.dst_cidr, pkt.dst_ip):
            return False
        if not self._port_matches(self.src_port, pkt.src_port):
            return False
        if not self._port_matches(self.dst_port, pkt.dst_port):
            return False
        if self.schedule and not self._in_schedule(self.schedule):
            return False
        return True

    def _ip_matches(self, cidr: str, ip: str) -> bool:
        if cidr.upper() == "ANY":
            return True
        try:
            return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False

    def _port_matches(self, spec: str, port: int) -> bool:
        if spec.upper() == "ANY":
            return True
        if "-" in spec:
            lo, hi = map(int, spec.split("-"))
            return lo <= port <= hi
        return int(spec) == port

    def _in_schedule(self, sched: str) -> bool:
        m = re.match(r"schedule:(\d{2}:\d{2})-(\d{2}:\d{2})", sched)
        if not m:
            return True
        start = time.fromisoformat(m.group(1))
        end = time.fromisoformat(m.group(2))
        now = datetime.now().time()
        if start <= end:
            return start <= now <= end
        return now >= start or now <= end  # overnight window

def load_rules(path: str) -> List[Rule]:
    rules = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            # Format: ACTION PROTO SRC_CIDR SRC_PORT -> DST_CIDR DST_PORT [schedule:...]
            parts = line.split()
            if "->" not in parts:
                continue
            arrow = parts.index("->")
            left = parts[:arrow]
            right = parts[arrow + 1:]
            action, proto, src_cidr, src_port = left[0], left[1], left[2], left[3]
            dst_cidr, dst_port = right[0], right[1]
            schedule = right[2] if len(right) > 2 else None
            rules.append(Rule(action, proto, src_cidr, src_port, dst_cidr, dst_port, schedule))
    return rules
