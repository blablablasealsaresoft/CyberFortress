#!/usr/bin/env python3
import argparse, json, os, shutil, platform, time
from pathlib import Path

EVIDENCE_DIR = os.environ.get('FORTRESS_EVIDENCE', '../../data/forensics')

BROWSERS = {
	'windows': [
		('Chrome', Path.home() / 'AppData/Local/Google/Chrome/User Data'),
		('Edge', Path.home() / 'AppData/Local/Microsoft/Edge/User Data'),
		('Firefox', Path.home() / 'AppData/Roaming/Mozilla/Firefox')
	],
	'linux': [
		('Chrome', Path.home() / '.config/google-chrome'),
		('Chromium', Path.home() / '.config/chromium'),
		('Firefox', Path.home() / '.mozilla/firefox')
	]
}

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--case-id', required=False)
	args = p.parse_args()
	case = args.case_id or str(int(time.time()))
	out_dir = Path(EVIDENCE_DIR) / case / 'browser'
	out_dir.mkdir(parents=True, exist_ok=True)
	sys = 'windows' if platform.system().lower() == 'windows' else 'linux'
	collected = []
	for name, path in BROWSERS.get(sys, []):
		if path.exists():
			dest = out_dir / name
			try:
				shutil.copytree(path, dest, dirs_exist_ok=True)
				collected.append(str(dest))
			except Exception:
				pass
	print(json.dumps({"success": True, "artifacts": collected, "case_id": case})) 