#!/usr/bin/env python3
import argparse, json, os, time
import pandas as pd

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/ml'))
DATASETS = os.path.join(BASE, 'datasets')

os.makedirs(DATASETS, exist_ok=True)

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--name', required=True)
	p.add_argument('--csv', required=True)
	p.add_argument('--target', required=False, help='Target column for supervised tasks')
	args = p.parse_args()
	case = str(int(time.time()))
	try:
		df = pd.read_csv(args.csv)
		path = os.path.join(DATASETS, f'{args.name}.csv')
		df.to_csv(path, index=False)
		meta = {
			'name': args.name,
			'rows': len(df),
			'cols': list(df.columns),
			'target': args.target or None,
			'created_at': case
		}
		open(os.path.join(DATASETS, f'{args.name}.meta.json'), 'w').write(json.dumps(meta))
		print(json.dumps({'success': True, 'dataset': args.name, 'path': path, 'meta': meta}))
	except Exception as e:
		print(json.dumps({'success': False, 'error': str(e)})) 