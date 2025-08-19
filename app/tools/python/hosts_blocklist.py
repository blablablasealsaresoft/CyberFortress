#!/usr/bin/env python3
import argparse, json, os, shutil, requests, platform

STEVENBLACK = 'https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts'

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--source', default=STEVENBLACK)
	args = p.parse_args()
	try:
		resp = requests.get(args.source, timeout=30)
		resp.raise_for_status()
		content = resp.text
		if platform.system().lower() == 'windows':
			hosts = r'C:\\Windows\\System32\\drivers\\etc\\hosts'
		else:
			hosts = '/etc/hosts'
		backup = hosts + '.fortress.bak'
		try:
			shutil.copyfile(hosts, backup)
		except Exception:
			pass
		with open(hosts, 'w', encoding='utf-8', errors='ignore') as f:
			f.write(content)
		print(json.dumps({"success": True, "hosts": hosts, "backup": backup}))
	except Exception as e:
		print(json.dumps({"success": False, "error": str(e)})) 