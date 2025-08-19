#!/usr/bin/env python3
import argparse, json, requests, time

PLATFORMS = {
	'github': 'https://github.com/{u}',
	'twitter': 'https://x.com/{u}',
	'instagram': 'https://www.instagram.com/{u}/',
	'linkedin': 'https://www.linkedin.com/in/{u}/',
	'reddit': 'https://www.reddit.com/user/{u}/',
	'facebook': 'https://www.facebook.com/{u}'
}

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--username', required=True)
	args = p.parse_args()
	r = {}
	for k, url in PLATFORMS.items():
		u = url.format(u=args.username)
		try:
			resp = requests.get(u, timeout=8, headers={'user-agent':'Fortress/OSINT'})
			r[k] = (resp.status_code != 404)
		except Exception:
			r[k] = None
	print(json.dumps({'username': args.username, 'presence': r})) 