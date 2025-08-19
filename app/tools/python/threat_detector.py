#!/usr/bin/env python3
import argparse
import json
import time
import psutil
import subprocess
from datetime import datetime
from typing import Dict, List

SUSPICIOUS_PROCESSES = [
	"nc","netcat","ncat","xmrig","mimikatz","lazagne","procdump","gsecdump"
]
SUSPICIOUS_PORTS = {4444,5555,6666,6667,7777,8080,9999,12345,31337,65535}
CRITICAL_FILES = ["/etc/passwd","/etc/shadow","/etc/sudoers","/etc/ssh/sshd_config","/etc/hosts","/etc/crontab"]


def log(event: Dict):
	print(json.dumps({**event, "ts": datetime.utcnow().isoformat()}))


def check_processes():
	for proc in psutil.process_iter(['pid','name','cmdline']):
		try:
			name = (proc.info.get('name') or '').lower()
			if any(s in name for s in SUSPICIOUS_PROCESSES):
				log({"type":"suspicious_process","severity":"HIGH","pid":proc.info['pid'],"name":name})
			cmd = ' '.join(proc.info.get('cmdline') or [])
			if 'wget http' in cmd or 'curl http' in cmd:
				log({"type":"malware_pattern","severity":"CRITICAL","pid":proc.info['pid'],"cmd":cmd[:140]})
		except psutil.Error:
			continue


def check_network():
	for conn in psutil.net_connections(kind='inet'):
		try:
			if conn.raddr and conn.raddr.port in SUSPICIOUS_PORTS:
				log({"type":"suspicious_port","severity":"MEDIUM","remote":f"{conn.raddr.ip}:{conn.raddr.port}"})
		except Exception:
			pass


def check_files():
	for path in CRITICAL_FILES:
		try:
			with open(path,'rb') as f:
				_ = f.read(1)
		except Exception:
			log({"type":"file_issue","severity":"HIGH","path":path})


def auto_response(event: Dict):
	if event.get('type') == 'suspicious_process' and event.get('pid'):
		try:
			subprocess.call(['sh','-c', f"kill -9 {event['pid']}"])
			log({"type":"action","action":"kill","pid":event['pid'],"result":"ok"})
		except Exception:
			pass


def run_loop(interval: int, respond: bool):
	while True:
		check_processes()
		check_network()
		check_files()
		# optional response is demo only
		if respond:
			auto_response({"type":"noop"})
		time.sleep(interval)


def main():
	p = argparse.ArgumentParser(description='Threat detector')
	p.add_argument('--interval', type=int, default=5)
	p.add_argument('--respond', action='store_true')
	args = p.parse_args()
	run_loop(args.interval, args.respond)

if __name__ == '__main__':
	main() 