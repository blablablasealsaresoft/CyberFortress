#!/usr/bin/env python3
import argparse, json, os, subprocess, time

EVIDENCE_DIR = os.environ.get('FORTRESS_EVIDENCE','../../data/forensics')

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--case-id', required=False)
	p.add_argument('--yara-rules', required=False)
	args = p.parse_args()
	case = args.case_id or str(int(time.time()))
	artifacts = {}
	def run(cmd):
		try:
			out = subprocess.check_output(cmd, text=True)
			return out
		except Exception as e:
			return str(e)
	artifacts['memory'] = json.loads(subprocess.getoutput(f'python3 forensic_memory.py --case-id {case}') or '{}')
	artifacts['events'] = json.loads(subprocess.getoutput(f'python3 forensic_event_logs.py --case-id {case}') or '{}')
	artifacts['browser'] = json.loads(subprocess.getoutput(f'python3 forensic_browser_artifacts.py --case-id {case}') or '{}')
	artifacts['registry'] = json.loads(subprocess.getoutput(f'python3 forensic_registry_dump.py --case-id {case}') or '{}')
	if args.yara_rules:
		artifacts['yara'] = json.loads(subprocess.getoutput(f'python3 forensic_yara_scan.py --rules {args.yara_rules} --path .') or '{}')
	report_path = os.path.join(EVIDENCE_DIR, case, 'triage_report.json')
	os.makedirs(os.path.dirname(report_path), exist_ok=True)
	open(report_path,'w').write(json.dumps(artifacts))
	print(json.dumps({"success": True, "case_id": case, "report": report_path})) 