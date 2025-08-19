#!/usr/bin/env python3
import argparse, json, os, glob

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/ml'))
MODELS = os.path.join(BASE, 'models')
PROMO = os.path.join(BASE, 'production.json')
STATUS = os.path.join(BASE, 'status.json')

os.makedirs(MODELS, exist_ok=True)

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest='action', required=True)
	sub.add_parser('list')
	pr = sub.add_parser('promote'); pr.add_argument('--model', required=True)
	sub.add_parser('status')
	args = p.parse_args()
	if args.action == 'list':
		items = []
		for f in glob.glob(os.path.join(MODELS, '*.joblib.meta.json')):
			try:
				items.append(json.load(open(f,'r')))
			except Exception:
				pass
		print(json.dumps({'models': items}))
	elif args.action == 'promote':
		open(PROMO,'w').write(json.dumps({'model': args.model}))
		print(json.dumps({'success': True, 'production': args.model}))
	elif args.action == 'status':
		try:
			print(open(STATUS,'r').read())
		except Exception:
			print(json.dumps({'running': False})) 