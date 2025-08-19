#!/usr/bin/env python3
import argparse, json, os, platform, subprocess, time

EVIDENCE_DIR = os.environ.get('FORTRESS_EVIDENCE', '../../data/forensics')

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--case-id', required=False)
	p.add_argument('--since', required=False)
	p.add_argument('--until', required=False)
	args = p.parse_args()
	case = args.case_id or str(int(time.time()))
	out_dir = os.path.join(EVIDENCE_DIR, case)
	os.makedirs(out_dir, exist_ok=True)
	artifacts = []
	if platform.system().lower() == 'windows':
		for ch in ['System','Application','Security']:
			path = os.path.join(out_dir, f'{ch}.evtx')
			cmd = ['wevtutil','epl', ch, path]
			subprocess.call(cmd)
			artifacts.append(path)
	else:
		path = os.path.join(out_dir, f'journal_{case}.log')
		cmd = 'journalctl -o short-iso'
		if args.since: cmd += f' --since {args.since}'
		if args.until: cmd += f' --until {args.until}'
		out = subprocess.getoutput(cmd)
		open(path, 'w').write(out)
		artifacts.append(path)
	print(json.dumps({"success": True, "artifacts": artifacts, "case_id": case})) 