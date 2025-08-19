#!/usr/bin/env python3
import argparse, json, os, time, joblib
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/ml'))
MODELS = os.path.join(BASE, 'models'); os.makedirs(MODELS, exist_ok=True)
DATASETS = os.path.join(BASE, 'datasets')
STATUS = os.path.join(BASE, 'status.json')


def write_status(status: dict):
	open(STATUS,'w').write(json.dumps(status))

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--dataset', required=True)
	p.add_argument('--algo', choices=['iforest','rf'], default='iforest')
	p.add_argument('--target', required=False)
	args = p.parse_args()
	try:
		write_status({'running': True, 'dataset': args.dataset, 'algo': args.algo, 'started_at': int(time.time())})
		df = pd.read_csv(os.path.join(DATASETS, f'{args.dataset}.csv'))
		model_path = os.path.join(MODELS, f'{args.dataset}_{args.algo}.joblib')
		metrics = {}
		if args.algo == 'iforest':
			model = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
			model.fit(df.select_dtypes(include=['number']).fillna(0.0))
		else:
			target = args.target
			if not target or target not in df.columns:
				raise RuntimeError('target column required for rf')
			X = df.drop(columns=[target]).select_dtypes(include=['number']).fillna(0.0)
			y = df[target]
			Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42)
			model = RandomForestClassifier(n_estimators=200, random_state=42)
			model.fit(Xtr, ytr)
			pred = model.predict(Xte)
			rep = classification_report(yte, pred, output_dict=True)
			metrics['classification_report'] = rep
		joblib.dump({'model': model}, model_path)
		meta = {'dataset': args.dataset, 'algo': args.algo, 'model_path': model_path, 'metrics': metrics, 'created_at': int(time.time())}
		open(model_path + '.meta.json','w').write(json.dumps(meta))
		write_status({'running': False, 'success': True, 'model': model_path, 'metrics': metrics})
		print(json.dumps({'success': True, 'model': model_path, 'metrics': metrics}))
	except Exception as e:
		write_status({'running': False, 'success': False, 'error': str(e)})
		print(json.dumps({'success': False, 'error': str(e)})) 