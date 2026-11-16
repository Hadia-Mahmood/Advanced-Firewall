import logging
import subprocess
import sys
import time
from dataclasses import dataclass

from scapy.all import IP, TCP, UDP, ICMP, Raw

from rules import load_rules, Rule
from state_table import StateTable
from rate_limiter import SlidingWindowLimiter

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("firewall")

@dataclass
class Packet:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    proto: str          # TCP / UDP / ICMP
    tcp_flags: str = "" # S, SA, A, FA, F, R
    payload: bytes = b""
    raw: bytes = b""

    @classmethod
    def from_scapy(cls, ip_pkt):
        proto = "TCP" if ip_pkt.haslayer(TCP) else \
                "UDP" if ip_pkt.haslayer(UDP) else \
                "ICMP" if ip_pkt.haslayer(ICMP) else "OTHER"
        sport = dport = 0
        flags = ""
        if ip_pkt.haslayer(TCP):
            sport, dport = ip_pkt[TCP].sport, ip_pkt[TCP].dport
            flags = ip_pkt[TCP].sprintf("%flags%")
        elif ip_pkt.haslayer(UDP):
            sport, dport = ip_pkt[UDP].sport, ip_pkt[UDP].dport
        payload = bytes(ip_pkt[Raw].load) if ip_pkt.haslayer(Raw) else b""
        return cls(ip_pkt[IP].src, ip_pkt[IP].dst, sport, dport, proto, flags,
                   payload, bytes(ip_pkt))

class AdvancedFirewall:
    def __init__(self, rules_path: str, default_policy="DENY",
                 rate_limit=0, dpi_callback=None):
        self.rules = load_rules(rules_path)
        self.default_policy = default_policy.upper()
        self.state = StateTable()
        self.rate_limiter = SlidingWindowLimiter(rate_limit) if rate_limit > 0 else None
        self.dpi_callback = dpi_callback  # optional callable(pkt) -> bool (True=allow)

    def process(self, pkt: Packet) -> str:
        # 1. Rate limit
        if self.rate_limiter and not self.rate_limiter.allow(pkt.src_ip):
            log.warning("Rate‑limited %s", pkt.src_ip)
            return "DENY"

        # 2. Stateful fast‑path
        if self.state.is_established(pkt):
            self.state.update(pkt, "ALLOW")
            return "ALLOW"

        # 3. Optional DPI (must return False to block)
        if self.dpi_callback and not self.dpi_callback(pkt):
            log.info("DPI blocked %s:%s -> %s:%s", pkt.src_ip, pkt.src_port, pkt.dst_ip, pkt.dst_port)
            return "DENY"

        # 4. Rule matching (first match wins)
        action = self.default_policy
        for rule in self.rules:
            if rule.matches(pkt):
                action = rule.action
                break

        # 5. Update state only for allowed connections
        self.state.update(pkt, action)
        return action

# ---------- live mode: NetfilterQueue ----------
def run_live(iface: str, fw: AdvancedFirewall, queue_num=0):
    from netfilterqueue import NetfilterQueue

    def callback(nf_packet):
        ip_pkt = IP(nf_packet.get_payload())
        pkt = Packet.from_scapy(ip_pkt)
        action = fw.process(pkt)
        if action == "ALLOW":
            nf_packet.accept()
        else:
            nf_packet.drop()

    # Redirect traffic to NFQUEUE via iptables (adjust chains as needed)
    subprocess.run(["iptables", "-I", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(queue_num)], check=True)
    subprocess.run(["iptables", "-I", "INPUT",   "-j", "NFQUEUE", "--queue-num", str(queue_num)], check=True)
    subprocess.run(["iptables", "-I", "OUTPUT",  "-j", "NFQUEUE", "--queue-num", str(queue_num)], check=True)

    nfq = NetfilterQueue()
    nfq.bind(queue_num, callback)
    log.info("Live firewall active on %s (queue %d)", iface, queue_num)
    try:
        nfq.run()
    finally:
        nfq.unbind()
        subprocess.run(["iptables", "-D", "FORWARD", "-j", "NFQUEUE", "--queue-num", str(queue_num)])
        subprocess.run(["iptables", "-D", "INPUT",   "-j", "NFQUEUE", "--queue-num", str(queue_num)])
        subprocess.run(["iptables", "-D", "OUTPUT",  "-j", "NFQUEUE", "--queue-num", str(queue_num)])

# ---------- simulation / demo ----------
def demo():
    rules_text = """
    # ACTION PROTO SRC_CIDR SRC_PORT -> DST_CIDR DST_PORT [schedule]
    ALLOW TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 443
    ALLOW TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 1024-65535
    ALLOW UDP 0.0.0.0/0 ANY -> 0.0.0.0/0 53
    DENY  TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 22
    DENY  TCP 0.0.0.0/0 ANY -> 0.0.0.0/0 23
    LOG   ICMP 0.0.0.0/0 ANY -> 0.0.0.0/0 ANY
    """
    with open("/tmp/fw.rules", "w") as f:
        f.write(rules_text)

    fw = AdvancedFirewall("/tmp/fw.rules", default_policy="DENY", rate_limit=100)

    test_pkts = [
        Packet("192.168.1.10", "1.1.1.1", 12345, 443, "TCP", "S"),
        Packet("203.0.113.5", "192.168.1.10", 6543, 22, "TCP", "S"),   # SSH → DENY
        Packet("192.168.1.10", "8.8.8.8", 5353, 53, "UDP"),
        Packet("10.0.0.1", "10.0.0.2", 0, 0, "ICMP"),
    ]
    for p in test_pkts:
        act = fw.process(p)
        print(f"{act:5s}  {p.proto:4s}  {p.src_ip}:{p.src_port} -> {p.dst_ip}:{p.dst_port}")

if __name__ == "__main__":
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument("--live", metavar="IFACE", help="run in live mode on interface")
    ap.add_argument("--rules", default="rules.txt")
    ap.add_argument("--policy", default="DENY", choices=["ALLOW", "DENY"])
    ap.add_argument("--rate-limit", type=int, default=0, help="max packets/sec per source IP")
    ap.add_argument("--demo", action="store_true")
    args = ap.parse_args()

    if args.demo or not args.live:
        demo()
    else:
        fw = AdvancedFirewall(args.rules, default_policy=args.policy, rate_limit=args.rate_limit)
        run_live(args.live, fw)
