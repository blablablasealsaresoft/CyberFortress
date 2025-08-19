#!/usr/bin/env python3
import argparse, json, os, platform, subprocess, time

EVIDENCE_DIR = os.environ.get('FORTRESS_EVIDENCE', '../../data/forensics')

HIVES = [
	('HKLM','SAM'),
	('HKLM','SYSTEM'),
	('HKLM','SECURITY'),
	('HKLM','SOFTWARE'),
	('HKU','DEFAULT'),
]

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--case-id', required=False)
	args = p.parse_args()
	case = args.case_id or str(int(time.time()))
	out_dir = os.path.join(EVIDENCE_DIR, case, 'registry')
	os.makedirs(out_dir, exist_ok=True)
	artifacts = []
	if platform.system().lower() == 'windows':
		for root, name in HIVES:
			path = os.path.join(out_dir, f'{root}_{name}.hiv')
			subprocess.call(['reg','save', f'{root}\\{name}', path, '/y'])
			artifacts.append(path)
	print(json.dumps({"success": True, "artifacts": artifacts, "case_id": case})) 