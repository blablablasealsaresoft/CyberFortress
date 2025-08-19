#!/usr/bin/env python3
import argparse, json, os, requests

API = 'https://haveibeenpwned.com/api/v3/breachedaccount/'

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--email', required=True)
	p.add_argument('--api-key', required=False)
	args = p.parse_args()
	api_key = args.api_key or os.environ.get('HIBP_API_KEY')
	if not api_key:
		print(json.dumps({"available": False, "note": "HIBP API key required"}))
		exit(0)
	try:
		r = requests.get(API + args.email, headers={'hibp-api-key': api_key, 'user-agent': 'Fortress/1.0'}, params={'truncateResponse': 'true'}, timeout=20)
		if r.status_code == 200:
			print(json.dumps({"available": True, "breaches": r.json()}))
		else:
			print(json.dumps({"available": True, "status": r.status_code}))
	except Exception as e:
		print(json.dumps({"available": True, "error": str(e)})) 