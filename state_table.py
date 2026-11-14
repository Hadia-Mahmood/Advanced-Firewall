import time
from enum import Enum

class TcpState(Enum):
    SYN_SENT = "SYN_SENT"
    ESTABLISHED = "ESTABLISHED"
    FIN_WAIT = "FIN_WAIT"
    CLOSED = "CLOSED"

class StateTable:
    def __init__(self, tcp_timeout=300, udp_timeout=30, icmp_timeout=10):
        self.tcp_timeout = tcp_timeout
        self.udp_timeout = udp_timeout
        self.icmp_timeout = icmp_timeout
        self.conns = {}  # key: (proto, src_ip, src_port, dst_ip, dst_port)

    def _key(self, pkt):
        return (pkt.proto, pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)

    def is_established(self, pkt) -> bool:
        key = self._key(pkt)
        entry = self.conns.get(key)
        if not entry:
            return False
        state, last_seen = entry
        if time.time() - last_seen > self._timeout_for(pkt.proto):
            del self.conns[key]
            return False
        return state == "ESTABLISHED"

    def update(self, pkt, action: str):
        if action != "ALLOW":
            return
        key = self._key(pkt)
        now = time.time()

        if pkt.proto == "TCP":
            flags = pkt.tcp_flags
            current = self.conns.get(key, (None, 0))[0]
            if flags == "S":          # SYN
                if current is None:
                    self.conns[key] = ("SYN_SENT", now)
            elif flags == "SA":       # SYN‑ACK
                # reverse direction is handled by the caller; we simply mark forward
                rev_key = (pkt.proto, pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)
                if self.conns.get(rev_key, (None,))[0] == "SYN_SENT":
                    self.conns[key] = ("ESTABLISHED", now)
                    self.conns[rev_key] = ("ESTABLISHED", now)
            elif flags == "A" and current == "SYN_SENT":
                self.conns[key] = ("ESTABLISHED", now)
            elif flags == "FA" or flags == "F":
                self.conns[key] = ("FIN_WAIT", now)
            elif flags == "R":
                self.conns.pop(key, None)
            else:
                if current == "ESTABLISHED":
                    self.conns[key] = ("ESTABLISHED", now)
        else:
            # UDP / ICMP: simple session table
            self.conns[key] = ("ESTABLISHED", now)
            # also track reverse direction for replies
            rev_key = (pkt.proto, pkt.dst_ip, pkt.dst_port, pkt.src_ip, pkt.src_port)
            self.conns[rev_key] = ("ESTABLISHED", now)

    def _timeout_for(self, proto):
        return {"TCP": self.tcp_timeout,
                "UDP": self.udp_timeout,
                "ICMP": self.icmp_timeout}.get(proto, 10)
