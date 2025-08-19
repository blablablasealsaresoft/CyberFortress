#!/usr/bin/env python3
import argparse
import requests
import subprocess
import sys
from typing import List, Set


def download_ip_ranges(country_code: str) -> Set[str]:
	url = f"https://www.ipdeny.com/ipblocks/data/countries/{country_code.lower()}.zone"
	try:
		resp = requests.get(url, timeout=15)
		if resp.status_code == 200:
			return set([line.strip() for line in resp.text.splitlines() if line.strip() and not line.startswith('#')])
	except Exception:
		pass
	return set()


def sh(cmd: str) -> None:
	rc = subprocess.call(["sh", "-c", cmd])
	if rc != 0:
		raise SystemExit(f"command failed: {cmd}")


def ensure_ipset(name: str) -> None:
	# create if missing, then flush
	subprocess.call(["ipset", "create", name, "hash:net", "hashsize", "4096"], stderr=subprocess.DEVNULL)
	subprocess.call(["ipset", "flush", name], stderr=subprocess.DEVNULL)


def block_countries(countries: List[str]) -> None:
	ensure_ipset("geo_block")
	for c in countries:
		for ipr in download_ip_ranges(c):
			subprocess.call(["ipset", "add", "geo_block", ipr], stderr=subprocess.DEVNULL)
	# attach to INPUT
	subprocess.call(["iptables", "-D", "INPUT", "-m", "set", "--match-set", "geo_block", "src", "-j", "DROP"], stderr=subprocess.DEVNULL)
	sh("iptables -I INPUT 1 -m set --match-set geo_block src -j DROP")
	sh("iptables -I INPUT 1 -m set --match-set geo_block src -j LOG --log-prefix 'GEO-BLOCKED: '")


def whitelist_countries(countries: List[str]) -> None:
	ensure_ipset("geo_allow")
	for c in countries:
		for ipr in download_ip_ranges(c):
			subprocess.call(["ipset", "add", "geo_allow", ipr], stderr=subprocess.DEVNULL)
	# Only allow those in geo_allow, drop others
	sh("iptables -I INPUT 1 -m set ! --match-set geo_allow src -j DROP")


def main() -> None:
	if sys.platform.startswith("win"):
		print("Geo blocking is Linux-only (ipset/iptables required)")
		sys.exit(0)
	parser = argparse.ArgumentParser(description="Geographic IP blocking")
	parser.add_argument("mode", choices=["block", "whitelist"], help="Mode: block or whitelist")
	parser.add_argument("countries", help="Comma-separated country codes, e.g., CN,RU,IR")
	args = parser.parse_args()
	countries = [c.strip().upper() for c in args.countries.split(",") if c.strip()]
	if args.mode == "block":
		block_countries(countries)
	else:
		whitelist_countries(countries)
	print("OK")


if __name__ == "__main__":
	main() 