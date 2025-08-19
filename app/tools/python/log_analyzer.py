#!/usr/bin/env python3
import argparse
import gzip
import json
import os
import re
from datetime import datetime
from collections import defaultdict, Counter
import numpy as np
from sklearn.cluster import DBSCAN
from sklearn.preprocessing import StandardScaler

LOG_SOURCES = {
	'auth': '/var/log/auth.log',
	'syslog': '/var/log/syslog',
	'apache': '/var/log/apache2/access.log',
	'nginx': '/var/log/nginx/access.log',
	'kernel': '/var/log/kern.log',
	'firewall': '/var/log/ufw.log'
}

PATTERNS = {
	'ssh_failed': re.compile(r'Failed password for (\S+) from (\S+) port (\d+)'),
	'http_status': re.compile(r'(\S+)\s+\S+\s+\S+\s+\[(.*?)\]\s+"(\S+)\s+(\S+)\s+\S+"\s+(\d+)\s+(\d+)'),
	'sql_injection': re.compile(r'(union.*select|select.*from|drop.*table|insert.*into)', re.IGNORECASE),
	'xss': re.compile(r'(<script|javascript:|onerror=|onload=)', re.IGNORECASE),
}

def parse_file(path: str, log_type: str):
	if not os.path.exists(path):
		return []
	open_func = gzip.open if path.endswith('.gz') else open
	mode = 'rt' if path.endswith('.gz') else 'r'
	events = []
	with open_func(path, mode) as f:
		for line in f:
			if m := PATTERNS['ssh_failed'].search(line):
				events.append({"type":"ssh_failed","user":m.group(1),"source_ip":m.group(2),"port":m.group(3)})
			elif log_type in ['apache','nginx'] and (m := PATTERNS['http_status'].search(line)):
				events.append({"type":"http_request","client_ip":m.group(1),"method":m.group(3),"url":m.group(4),"status":int(m.group(5)),"size":int(m.group(6))})
				if PATTERNS['sql_injection'].search(line) or PATTERNS['xss'].search(line):
					events[-1].setdefault('indicators',[]).append('web_attack')
	return events


def correlate(events):
	bucket = defaultdict(list)
	for e in events:
		bucket[int(datetime.utcnow().timestamp()/300)].append(e)
	findings = []
	for _, items in bucket.items():
		ssh = [e for e in items if e['type']=='ssh_failed']
		if len(ssh) > 5:
			cnt = Counter([e['source_ip'] for e in ssh])
			for ip,c in cnt.items():
				if c>5:
					findings.append({"type":"brute_force","source_ip":ip,"count":c,"severity":"HIGH"})
		web = [e for e in items if e['type']=='http_request' and 'web_attack' in e.get('indicators',[])]
		if web:
			cnt = Counter([e.get('client_ip') for e in web])
			for ip,c in cnt.items():
				if c>10:
					findings.append({"type":"web_attack","source_ip":ip,"count":c,"severity":"HIGH"})
	return findings


def anomalies(events):
	rows = [[e.get('status',200), e.get('size',0), len(e.get('url',''))] for e in events if e['type']=='http_request']
	if len(rows) < 10:
		return []
	X = np.array(rows)
	sc = StandardScaler().fit(X)
	labels = DBSCAN(eps=0.8, min_samples=5).fit_predict(sc.transform(X))
	return [i for i,l in enumerate(labels) if l==-1]


def main():
	p = argparse.ArgumentParser(description='Log analyzer')
	args = p.parse_args()
	all_events = []
	for name,path in LOG_SOURCES.items():
		all_events.extend(parse_file(path, name))
	corr = correlate(all_events)
	anom = anomalies(all_events)
	print(json.dumps({"events": len(all_events), "findings": corr, "anomalies": anom}))

if __name__ == '__main__':
	main() 