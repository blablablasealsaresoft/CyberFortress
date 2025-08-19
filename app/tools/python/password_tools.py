#!/usr/bin/env python3
import argparse, json, secrets, string, hashlib, requests

def generate(length: int = 20, symbols: bool = True) -> dict:
	alphabet = string.ascii_letters + string.digits + (string.punctuation if symbols else '')
	pwd = ''.join(secrets.choice(alphabet) for _ in range(length))
	entropy = len(alphabet).bit_length() * length
	return {"password": pwd, "length": length, "entropy_bits_est": entropy}


def pwned_count(password: str) -> int:
	sha1 = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
	prefix, suffix = sha1[:5], sha1[5:]
	r = requests.get(f"https://api.pwnedpasswords.com/range/{prefix}", timeout=15)
	if r.status_code != 200:
		return -1
	for line in r.text.splitlines():
		try:
			chunk, count = line.strip().split(':')
			if chunk.upper() == suffix:
				return int(count)
		except Exception:
			continue
	return 0

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest='action', required=True)
	g = sub.add_parser('generate'); g.add_argument('--length', type=int, default=20); g.add_argument('--no-symbols', action='store_true')
	c = sub.add_parser('check'); c.add_argument('--password', required=True)
	args = p.parse_args()
	if args.action == 'generate':
		print(json.dumps(generate(args.length, symbols=not args.no_symbols)))
	elif args.action == 'check':
		print(json.dumps({"pwned_count": pwned_count(args.password)})) 