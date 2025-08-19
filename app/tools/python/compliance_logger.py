#!/usr/bin/env python3
import argparse, json, os, time

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/compliance'))
LOG = os.path.join(BASE, 'audit.jsonl')
os.makedirs(BASE, exist_ok=True)

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest='action', required=True)
	lg = sub.add_parser('log'); lg.add_argument('--action', required=True); lg.add_argument('--actor', required=True); lg.add_argument('--target', required=True); lg.add_argument('--result', required=True); lg.add_argument('--metadata', required=False)
	rp = sub.add_parser('report'); rp.add_argument('--period', default='daily')
	args = p.parse_args()
	if args.action == 'log':
		entry = { 'timestamp': int(time.time()), 'action': args.action, 'actor': args.actor, 'target': args.target, 'result': args.result, 'metadata': json.loads(args.metadata) if args.metadata else {} }
		with open(LOG,'a') as f: f.write(json.dumps(entry) + '\n')
		print(json.dumps({'success': True}))
	elif args.action == 'report':
		items = []
		try:
			with open(LOG,'r') as f:
				for line in f:
					items.append(json.loads(line))
		except Exception:
			pass
		rep = { 'total': len(items) }
		print(json.dumps({'success': True, 'report': rep})) 