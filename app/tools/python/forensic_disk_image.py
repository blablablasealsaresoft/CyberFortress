#!/usr/bin/env python3
import argparse, json, os, hashlib, zipfile, time
from pathlib import Path

EVIDENCE_DIR = os.environ.get('FORTRESS_EVIDENCE', '../../data/forensics')

def sha256_file(p: Path) -> str:
	try:
		h = hashlib.sha256()
		with open(p, 'rb') as f:
			for chunk in iter(lambda: f.read(8192), b''):
				h.update(chunk)
		return h.hexdigest()
	except Exception:
		return ''

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--target', required=True, help='File or directory to image')
	p.add_argument('--case-id', required=False)
	args = p.parse_args()
	case = args.case_id or str(int(time.time()))
	out_dir = Path(EVIDENCE_DIR) / case
	out_dir.mkdir(parents=True, exist_ok=True)
	manifest = []
	img_path = out_dir / f'image_{case}.zip'
	with zipfile.ZipFile(img_path, 'w', zipfile.ZIP_DEFLATED) as z:
		target = Path(args.target)
		if target.is_file():
			z.write(target, target.name)
			manifest.append({'path': target.name, 'sha256': sha256_file(target), 'size': target.stat().st_size})
		else:
			for root, _, files in os.walk(target):
				for name in files:
					p = Path(root) / name
					rel = str(p.relative_to(target))
					z.write(p, rel)
					manifest.append({'path': rel, 'sha256': sha256_file(p), 'size': p.stat().st_size})
	manifest_path = out_dir / f'manifest_{case}.json'
	open(manifest_path, 'w').write(json.dumps(manifest))
	print(json.dumps({"success": True, "image": str(img_path), "manifest": str(manifest_path), "case_id": case})) 