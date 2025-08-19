#!/usr/bin/env python3
import argparse, json, os, platform, subprocess, datetime

EVIDENCE_DIR = os.environ.get('FORTRESS_EVIDENCE', '../../data/forensics')

def ensure_dir(case_id: str) -> str:
	path = os.path.join(EVIDENCE_DIR, case_id)
	os.makedirs(path, exist_ok=True)
	return path

def windows_memory_capture(out_path: str) -> str:
	# Try winpmem if available in PATH
	try:
		cmd = ['winpmem_mini_x64.exe', out_path]
		subprocess.check_call(cmd)
		return out_path
	except Exception:
		return ''

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--case-id', required=False, default=datetime.datetime.utcnow().strftime('%Y%m%d%H%M%S'))
	args = p.parse_args()
	base = ensure_dir(args.case_id)
	artifact = ''
	sys = platform.system().lower()
	if sys == 'windows':
		out = os.path.join(base, f'memdump_{args.case_id}.raw')
		artifact = windows_memory_capture(out)
		if not artifact:
			# Fallback: dump process list as minimal memory context
			plist = subprocess.getoutput('wmic process get ProcessId,Name,CommandLine')
			open(os.path.join(base, f'process_list_{args.case_id}.txt'), 'w', encoding='utf-8', errors='ignore').write(plist)
			artifact = os.path.join(base, f'process_list_{args.case_id}.txt')
	elif sys == 'linux':
		# Placeholder: advise LiME/AVML deployment; collect /proc/meminfo
		meminfo = subprocess.getoutput('cat /proc/meminfo')
		open(os.path.join(base, f'meminfo_{args.case_id}.txt'), 'w').write(meminfo)
		artifact = os.path.join(base, f'meminfo_{args.case_id}.txt')
	else:
		artifact = ''
	print(json.dumps({"success": bool(artifact), "artifact": artifact, "case_id": args.case_id})) 