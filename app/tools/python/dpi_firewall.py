#!/usr/bin/env python3
import argparse
import asyncio
import subprocess
import re
import sys

try:
	import pyshark
except Exception as e:
	print("pyshark not available:", e)
	sys.exit(1)

SUSPICIOUS_USER_AGENTS = [
	"nikto", "sqlmap", "metasploit", "nmap", "masscan", "python-requests", "curl/", "wget/"
]

PATTERNS = {
	'sql_injection': [r"(\\bunion\\b.*\\bselect\\b)", r"(\\bselect\\b.*\\bfrom\\b.*\\bwhere\\b)", r"(\\bdrop\\b.*\\btable\\b)", r"(1\\s*=\\s*1)"],
	'xss': [r"<script[^>]*>.*?</script>", r"javascript:", r"on\\w+\\s*=", r"<iframe[^>]*>", r"eval\\s*\\("],
	'command_injection': [r";\\s*cat\\s+/etc/passwd", r";\\s*ls\\s+-la", r";\\s*wget\\s+", r";\\s*curl\\s+", r"\\|\\s*nc\\s+", r"`.*`", r"\\$\\(.*\\)"],
	'path_traversal': [r"\\.\\./\\.\\./", r"\\.\\.\\\\\\.\\.\\\\", r"/etc/passwd", r"/etc/shadow", r"c:\\\\windows\\\\system32"],
}


def sh(cmd: str) -> None:
	rc = subprocess.call(["sh", "-c", cmd])
	if rc != 0:
		raise SystemExit(f"command failed: {cmd}")


def block_ip(ip: str) -> None:
	# Best-effort block
	subprocess.call(['iptables', '-A', 'INPUT', '-s', ip, '-j', 'DROP'])
	print(f"[DPI] Blocked IP: {ip}")


async def analyze_packet(packet) -> None:
	try:
		if hasattr(packet, 'ip'):
			src_ip = packet.ip.src
			# HTTP checks
			if hasattr(packet, 'http'):
				if hasattr(packet.http, 'user_agent'):
					ua = packet.http.user_agent.lower()
					if any(sig in ua for sig in SUSPICIOUS_USER_AGENTS):
						print(f"[DPI] Suspicious UA {ua} from {src_ip}")
						block_ip(src_ip)
				if hasattr(packet.http, 'request_uri'):
					uri = packet.http.request_uri
					for plist in PATTERNS.values():
						for pat in plist:
							if re.search(pat, uri, re.IGNORECASE):
								print(f"[DPI] Suspicious URI from {src_ip}: {uri[:80]}")
								block_ip(src_ip)
			# DNS tunneling heuristics
			if hasattr(packet, 'dns') and hasattr(packet.dns, 'qry_name'):
				domain = packet.dns.qry_name
				if len(domain) > 120:
					print(f"[DPI] Possible DNS tunneling from {src_ip}: {domain[:80]}...")
					block_ip(src_ip)
	except Exception:
		pass


async def run(interface: str) -> None:
	print(f"[DPI] Starting capture on {interface}")
	capture = pyshark.LiveCapture(interface=interface)
	async for pkt in capture.sniff_continuously():
		await analyze_packet(pkt)


def main() -> None:
	if sys.platform.startswith('win'):
		print('DPI utility is Linux-focused. On Windows, pyshark may require WinPcap/Npcap and admin privileges.')
	parser = argparse.ArgumentParser(description='Deep Packet Inspection utility')
	parser.add_argument('--interface', default='eth0')
	args = parser.parse_args()
	asyncio.run(run(args.interface))


if __name__ == '__main__':
	main() 