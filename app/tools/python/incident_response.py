#!/usr/bin/env python3
import argparse
import json
import os
import shutil
import subprocess
from datetime import datetime

EVIDENCE_DIR = "/var/incident_response"
QUAR_DIR = "/var/quarantine"


def ensure_dirs():
	os.makedirs(EVIDENCE_DIR, exist_ok=True)
	os.makedirs(QUAR_DIR, exist_ok=True)


def block_ip(ip: str) -> str:
	try:
		subprocess.run(['iptables','-A','INPUT','-s',ip,'-j','DROP'], check=False)
		subprocess.run(['iptables','-A','OUTPUT','-d',ip,'-j','DROP'], check=False)
		return f"blocked {ip}"
	except Exception as e:
		return f"error {e}"


def quarantine(path: str) -> str:
	if not os.path.exists(path):
		return "missing"
	name = os.path.basename(path)
	dest = os.path.join(QUAR_DIR, f"{int(datetime.utcnow().timestamp())}_{name}")
	shutil.move(path, dest)
	os.chmod(dest, 0o400)
	return dest


def collect_artifacts(out_dir: str) -> str:
	os.makedirs(out_dir, exist_ok=True)
	with open(os.path.join(out_dir,'processes.txt'),'w') as f:
		f.write(subprocess.getoutput('ps auxww'))
	with open(os.path.join(out_dir,'netstat.txt'),'w') as f:
		f.write(subprocess.getoutput('ss -tunap || netstat -tunap'))
	return out_dir


def main():
	ensure_dirs()
	p = argparse.ArgumentParser(description='Incident responder')
	p.add_argument('--type', required=True, choices=['malware','intrusion','ddos','priv_esc'])
	p.add_argument('--ip')
	p.add_argument('--file')
	args = p.parse_args()
	inc_id = f"INC-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}"
	idir = os.path.join(EVIDENCE_DIR, inc_id)
	os.makedirs(idir, exist_ok=True)
	actions = []
	if args.ip:
		actions.append(block_ip(args.ip))
	if args.file:
		actions.append(quarantine(args.file))
	actions.append(collect_artifacts(os.path.join(idir,'artifacts')))
	print(json.dumps({"incident_id": inc_id, "actions": actions, "evidence": idir}))

if __name__ == '__main__':
	main() 