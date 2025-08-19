#!/usr/bin/env python3
import argparse, json, os, platform, shutil, subprocess, secrets

def linux_shred(path: str, passes: int) -> bool:
	try:
		subprocess.check_call(['sh','-lc', f'shred -uz -n {passes} -- {path}'])
		return True
	except Exception:
		return False

def overwrite_delete(path: str, passes: int) -> bool:
	try:
		size = os.path.getsize(path)
		for _ in range(passes):
			with open(path, 'r+b', buffering=0) as f:
				f.seek(0)
				remaining = size
				while remaining > 0:
					chunk = secrets.token_bytes(min(1024*1024, remaining))
					f.write(chunk)
					remaining -= len(chunk)
		os.remove(path)
		return True
	except Exception:
		return False

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--path', required=True)
	p.add_argument('--passes', type=int, default=3)
	args = p.parse_args()
	ok = False
	if platform.system().lower() == 'linux':
		ok = linux_shred(args.path, args.passes) or overwrite_delete(args.path, args.passes)
	else:
		ok = overwrite_delete(args.path, args.passes)
	print(json.dumps({"success": ok})) 