#!/usr/bin/env python3
import argparse, json, os, re, time, requests, tldextract
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/osint'))

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PHONE_RE = re.compile(r"\+?\d[\d\-\s\(\)]{7,}\d")


def ensure_case(case_id: str) -> str:
	path = os.path.join(BASE, case_id)
	os.makedirs(path, exist_ok=True)
	return path

def fetch(url: str) -> str:
	try:
		r = requests.get(url, timeout=15, headers={'user-agent':'Fortress/OSINT'})
		if r.ok:
			return r.text
	except Exception:
		pass
	return ''


def collect_from_html(html: str, base_url: str = None):
	soup = BeautifulSoup(html, 'html.parser')
	text = soup.get_text(" ")
	emails = sorted(set(EMAIL_RE.findall(text)))
	phones = sorted(set(PHONE_RE.findall(text)))
	links = []
	domains = set()
	for a in soup.find_all('a', href=True):
		href = a['href']
		if base_url:
			href = urljoin(base_url, href)
		links.append(href)
		d = urlparse(href).netloc
		if d:
			domains.add(tldextract.extract(d).registered_domain)
	return { 'emails': emails, 'phones': phones, 'links': sorted(set(links)), 'domains': sorted([d for d in domains if d]) }

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--case-id', required=False)
	p.add_argument('--target', required=True, help='URL or raw text')
	args = p.parse_args()
	case = args.case_id or str(int(time.time()))
	out_dir = ensure_case(case)
	if args.target.startswith('http://') or args.target.startswith('https://'):
		html = fetch(args.target)
		art = collect_from_html(html, args.target)
	else:
		art = { 'emails': sorted(set(EMAIL_RE.findall(args.target))), 'phones': sorted(set(PHONE_RE.findall(args.target))), 'links': [], 'domains': [] }
	open(os.path.join(out_dir, 'artifacts.json'), 'w').write(json.dumps(art))
	print(json.dumps({'success': True, 'case_id': case, 'artifacts': art})) 