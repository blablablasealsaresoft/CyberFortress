#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import time
from datetime import datetime
from pathlib import Path
from typing import Dict

CRITICAL_PATHS = [
	'/boot','/bin','/sbin','/lib','/lib64','/usr/bin','/usr/sbin','/usr/lib','/etc'
]

STATE_PATH = '/var/lib/fortress_integrity.json'


def sha256_file(path: str) -> str:
	try:
		with open(path,'rb') as f:
			h = hashlib.sha256()
			for chunk in iter(lambda: f.read(8192), b''):
				h.update(chunk)
			return h.hexdigest()
	except Exception:
		return ''


def load_state() -> Dict[str,str]:
	if os.path.exists(STATE_PATH):
		try:
			return json.load(open(STATE_PATH,'r'))
		except Exception:
			return {}
	return {}


def save_state(state: Dict[str,str]):
	os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
	json.dump(state, open(STATE_PATH,'w'))


def scan_once() -> Dict:
	state = load_state()
	changes = []
	for root in CRITICAL_PATHS:
		if not os.path.exists(root):
			continue
		for dirpath, _, filenames in os.walk(root):
			for name in filenames:
				path = os.path.join(dirpath, name)
				hashv = sha256_file(path)
				if not hashv:
					continue
				prev = state.get(path)
				if prev is None:
					changes.append({"type":"new_file","path":path})
				elif prev != hashv:
					changes.append({"type":"modified_file","path":path})
				state[path] = hashv
	save_state(state)
	return {"ts": datetime.utcnow().isoformat(), "changes": changes}


def main():
	p = argparse.ArgumentParser(description='Integrity monitor')
	p.add_argument('--interval', type=int, default=300)
	p.add_argument('--once', action='store_true')
	args = p.parse_args()
	if args.once:
		print(json.dumps(scan_once()))
		return
	while True:
		print(json.dumps(scan_once()))
		time.sleep(args.interval)

if __name__ == '__main__':
	main() 