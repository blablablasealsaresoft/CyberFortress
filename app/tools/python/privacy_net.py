#!/usr/bin/env python3
import argparse
import json
import os
import platform
import subprocess
import shlex
from typing import Dict


def linux_required():
	if platform.system().lower() != 'linux':
		print(json.dumps({"success": False, "error": "linux_only"}))
		raise SystemExit(0)


def sh(cmd: str) -> str:
	return subprocess.getoutput(cmd)


def run(cmd: str) -> int:
	return subprocess.call(["sh", "-lc", cmd])


# Tor transparent proxy ----------------------------------------------------------

def tor_transparent_enable() -> Dict:
	linux_required()
	# Install tor
	run("sudo apt-get update -y && sudo apt-get install -y tor iptables iproute2")
	# Detect tor user
	tor_uid = sh("id -u debian-tor || id -u tor || echo 0").strip() or "0"
	# Configure torrc
	torrc = "/etc/tor/torrc"
	torrc_frag = """
VirtualAddrNetworkIPv4 10.192.0.0/10
AutomapHostsOnResolve 1
TransPort 9040
DNSPort 5353
"""
	shcmd_inner = f"grep -q TransPort {torrc} || printf %s {shlex.quote(torrc_frag)} >> {torrc}"
	run("sudo bash -lc " + shlex.quote(shcmd_inner))
	# iptables rules
	run("sudo iptables -t nat -N TOR 2>/dev/null || true")
	run("sudo iptables -t nat -F TOR")
	# Exclude local and tor user
	run("sudo iptables -t nat -A TOR -d 127.0.0.0/8 -j RETURN")
	run("sudo iptables -t nat -A TOR -m owner --uid-owner %s -j RETURN" % tor_uid)
	# Redirect TCP to Tor TransPort
	run("sudo iptables -t nat -A TOR -p tcp --syn -j REDIRECT --to-ports 9040")
	# Apply to outgoing
	run("sudo iptables -t nat -D OUTPUT -p tcp -j TOR 2>/dev/null || true")
	run("sudo iptables -t nat -I OUTPUT 1 -p tcp -j TOR")
	# DNS to Tor DNSPort
	run("sudo iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null || true")
	run("sudo iptables -t nat -I OUTPUT 1 -p udp --dport 53 -j REDIRECT --to-ports 5353")
	# Killswitch: only allow Tor user to reach WAN for TCP/UDP, allow loopback
	run("sudo iptables -P OUTPUT DROP")
	run("sudo iptables -D OUTPUT -o lo -j ACCEPT 2>/dev/null || true")
	run("sudo iptables -I OUTPUT 1 -o lo -j ACCEPT")
	run("sudo iptables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	run(f"sudo iptables -I OUTPUT 1 -m owner --uid-owner {tor_uid} -j ACCEPT")
	return {"success": True, "tor_uid": tor_uid}


def tor_transparent_disable() -> Dict:
	linux_required()
	# Remove TOR chain usage
	run("sudo iptables -t nat -D OUTPUT -p tcp -j TOR 2>/dev/null || true")
	run("sudo iptables -t nat -D OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 5353 2>/dev/null || true")
	run("sudo iptables -t nat -F TOR 2>/dev/null || true")
	run("sudo iptables -t nat -X TOR 2>/dev/null || true")
	# Relax OUTPUT policy (best-effort)
	run("sudo iptables -P OUTPUT ACCEPT")
	return {"success": True}


# DNS privacy (Stubby/DNSCrypt) -------------------------------------------------

def stubby_enable() -> Dict:
	linux_required()
	run("sudo apt-get update -y && sudo apt-get install -y stubby")
	# Minimal recommended config already packaged; ensure service enabled and resolv points local
	run("sudo systemctl enable --now stubby")
	run("sudo sed -i 's/^nameserver .*/nameserver 127.0.0.1/' /etc/resolv.conf || true")
	return {"success": True}


def stubby_disable() -> Dict:
	linux_required()
	run("sudo systemctl disable --now stubby || true")
	return {"success": True}


def dnscrypt_enable() -> Dict:
	linux_required()
	run("sudo apt-get update -y && sudo apt-get install -y dnscrypt-proxy")
	run("sudo systemctl enable --now dnscrypt-proxy")
	# dnscrypt-proxy listens on 127.0.2.1:53 by default on Debian/Ubuntu
	run("sudo sed -i 's/^nameserver .*/nameserver 127.0.2.1/' /etc/resolv.conf || true")
	return {"success": True}


def dnscrypt_disable() -> Dict:
	linux_required()
	run("sudo systemctl disable --now dnscrypt-proxy || true")
	return {"success": True}


# WireGuard VPN + Kill Switch ---------------------------------------------------

def wg_apply(config_b64: str) -> Dict:
	import base64
	linux_required()
	run("sudo apt-get update -y && sudo apt-get install -y wireguard wireguard-tools")
	cfg = base64.b64decode(config_b64.encode()).decode()
	os.makedirs('/etc/wireguard', exist_ok=True)
	open('/etc/wireguard/wg0.conf','w').write(cfg)
	run("sudo wg-quick down wg0 2>/dev/null || true")
	run("sudo wg-quick up wg0")
	return {"success": True}


def wg_killswitch_enable() -> Dict:
	linux_required()
	# Allow loopback and wg0, established; drop others
	run("sudo iptables -D OUTPUT -o lo -j ACCEPT 2>/dev/null || true")
	run("sudo iptables -I OUTPUT 1 -o lo -j ACCEPT")
	run("sudo iptables -I OUTPUT 1 -o wg0 -j ACCEPT")
	run("sudo iptables -I OUTPUT 1 -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT")
	run("sudo iptables -P OUTPUT DROP")
	return {"success": True}


def wg_killswitch_disable() -> Dict:
	linux_required()
	run("sudo iptables -P OUTPUT ACCEPT")
	return {"success": True}


# Network namespace isolation ---------------------------------------------------

def netns_run(name: str, command: str) -> Dict:
	linux_required()
	run(f"sudo ip netns add {name} 2>/dev/null || true")
	# Basic loopback enable in ns
	run(f"sudo ip netns exec {name} ip link set lo up")
	# Execute command
	code = run(f"sudo ip netns exec {name} bash -lc {json.dumps(command)}")
	return {"success": code == 0, "exit_code": code}


if __name__ == '__main__':
	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest='action', required=True)
	sub.add_parser('tor-enable')
	sub.add_parser('tor-disable')
	sub.add_parser('stubby-enable')
	sub.add_parser('stubby-disable')
	sub.add_parser('dnscrypt-enable')
	sub.add_parser('dnscrypt-disable')
	wg = sub.add_parser('wg-apply'); wg.add_argument('--config-b64', required=True)
	sub.add_parser('wg-killswitch-enable')
	sub.add_parser('wg-killswitch-disable')
	ns = sub.add_parser('netns-run'); ns.add_argument('--name', required=True); ns.add_argument('--cmd', required=True)
	args = p.parse_args()

	if args.action == 'tor-enable': print(json.dumps(tor_transparent_enable()))
	elif args.action == 'tor-disable': print(json.dumps(tor_transparent_disable()))
	elif args.action == 'stubby-enable': print(json.dumps(stubby_enable()))
	elif args.action == 'stubby-disable': print(json.dumps(stubby_disable()))
	elif args.action == 'dnscrypt-enable': print(json.dumps(dnscrypt_enable()))
	elif args.action == 'dnscrypt-disable': print(json.dumps(dnscrypt_disable()))
	elif args.action == 'wg-apply': print(json.dumps(wg_apply(args.config_b64)))
	elif args.action == 'wg-killswitch-enable': print(json.dumps(wg_killswitch_enable()))
	elif args.action == 'wg-killswitch-disable': print(json.dumps(wg_killswitch_disable()))
	elif args.action == 'netns-run': print(json.dumps(netns_run(args.name, args.cmd))) 