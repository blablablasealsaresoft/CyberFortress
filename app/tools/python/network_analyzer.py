#!/usr/bin/env python3
import argparse
import json
import subprocess
from datetime import datetime, timedelta

try:
	from scapy.all import sniff, IP, TCP, UDP, ICMP
	has_scapy = True
except Exception:
	has_scapy = False


def analyze_ss():
	out = subprocess.check_output(['ss','-tunap'], text=True)
	lines = [l for l in out.splitlines() if l and not l.startswith('State')]
	return {"timestamp": datetime.utcnow().isoformat(), "connections": len(lines)}


def pkt_handler(pkt):
	info = {"ts": datetime.utcnow().isoformat()}
	if IP in pkt:
		info.update({"src": pkt[IP].src, "dst": pkt[IP].dst})
	if TCP in pkt:
		info.update({"proto": "TCP", "sport": pkt[TCP].sport, "dport": pkt[TCP].dport})
	elif UDP in pkt:
		info.update({"proto": "UDP", "sport": pkt[UDP].sport, "dport": pkt[UDP].dport})
	elif ICMP in pkt:
		info.update({"proto": "ICMP"})
	print(json.dumps(info))


def main():
	p = argparse.ArgumentParser(description='Network analyzer')
	p.add_argument('--interface', default='eth0')
	p.add_argument('--duration', type=int, default=60)
	args = p.parse_args()
	if has_scapy:
		end = datetime.utcnow() + timedelta(seconds=args.duration)
		sniff(iface=args.interface, prn=pkt_handler, stop_filter=lambda x: datetime.utcnow() > end)
	else:
		print(json.dumps(analyze_ss()))

if __name__ == '__main__':
	main() 