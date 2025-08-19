#!/usr/bin/env python3
import argparse, json, os

try:
	import yara
	has_yara = True
except Exception:
	has_yara = False

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--rules', required=True)
	p.add_argument('--path', required=True)
	args = p.parse_args()
	if not has_yara:
		print(json.dumps({"success": False, "error": "yara not available"}))
		raise SystemExit(0)
	rules = yara.compile(filepath=args.rules)
	findings = []
	for root, _, files in os.walk(args.path):
		for name in files:
			fp = os.path.join(root, name)
			try:
				matches = rules.match(fp)
				for m in matches:
					findings.append({'file': fp, 'rule': m.rule})
			except Exception:
				pass
	print(json.dumps({"success": True, "findings": findings})) 