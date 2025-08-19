#!/usr/bin/env python3
import argparse, json, requests

def harvest(target: str):
	indicators = []
	try:
		resp = requests.get(f'https://api.github.com/users/{target}', timeout=10)
		if resp.status_code == 200:
			data = resp.json(); indicators.append({'github': {'public_repos': data.get('public_repos'), 'followers': data.get('followers')}})
	except: pass
	return {'target': target, 'artifacts': indicators}

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--target', required=True)
	args = p.parse_args()
	print(json.dumps(harvest(args.target))) 