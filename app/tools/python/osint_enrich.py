#!/usr/bin/env python3
import argparse, json, os, socket, time
import tldextract
import dns.resolver
try:
	import whois as pywhois
	HAS_WHOIS=True
except Exception:
	HAS_WHOIS=False

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/osint'))

def ensure_case(case_id: str) -> str:
	path = os.path.join(BASE, case_id)
	os.makedirs(path, exist_ok=True)
	return path


def enrich_domain(domain: str):
	out = {'domain': domain, 'dns': {}, 'whois': {}}
	res = dns.resolver.Resolver()
	for rr in ['A','AAAA','MX','NS','TXT']:
		try:
			ans = res.resolve(domain, rr)
			out['dns'][rr] = [r.to_text() for r in ans]
		except Exception:
			out['dns'][rr] = []
	if HAS_WHOIS:
		try:
			w = pywhois.whois(domain)
			out['whois'] = {k: str(v) for k,v in w.__dict__.items() if not k.startswith('_')}
		except Exception:
			pass
	return out


def enrich_ip(ip: str):
	out = {'ip': ip}
	try:
		host,_,_ = socket.gethostbyaddr(ip)
		out['rdns'] = host
	except Exception:
		out['rdns'] = None
	return out


def enrich_email(email: str):
	domain = email.split('@')[-1]
	return {'email': email, 'domain': enrich_domain(domain)}

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--case-id', required=False)
	p.add_argument('--type', choices=['domain','ip','email'], required=True)
	p.add_argument('--value', required=True)
	args = p.parse_args()
	case = args.case_id or str(int(time.time()))
	ensure_case(case)
	if args.type=='domain': data = enrich_domain(args.value)
	elif args.type=='ip': data = enrich_ip(args.value)
	else: data = enrich_email(args.value)
	open(os.path.join(BASE, case, 'enrichment.json'),'w').write(json.dumps(data))
	print(json.dumps({'success': True, 'case_id': case, 'data': data})) 