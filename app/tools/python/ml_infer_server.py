#!/usr/bin/env python3
import argparse, json, os, joblib, threading
from flask import Flask, request, jsonify

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/ml'))
PROMO = os.path.join(BASE, 'production.json')
RUNTIME = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/runtime'))
PID_FILE = os.path.join(RUNTIME, 'ml_infer.pid')
app = Flask(__name__)
MODEL = None

@app.route('/score', methods=['POST'])
def score():
	global MODEL
	if MODEL is None:
		return jsonify({'error':'no_model'}), 400
	data = request.get_json(force=True)
	import pandas as pd
	X = pd.DataFrame([data]).select_dtypes(include=['number']).fillna(0.0)
	try:
		pred = MODEL['model'].predict(X)
		return jsonify({'prediction': pred[0] if len(pred)>0 else None})
	except Exception as e:
		return jsonify({'error': str(e)}), 500


def start(host: str, port: int):
	os.makedirs(RUNTIME, exist_ok=True)
	with open(PROMO,'r') as f:
		mpath = json.load(f)['model']
	global MODEL
	MODEL = joblib.load(mpath)
	open(PID_FILE,'w').write(str(os.getpid()))
	app.run(host=host, port=port)

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest='action', required=True)
	st = sub.add_parser('start'); st.add_argument('--host', default='127.0.0.1'); st.add_argument('--port', type=int, default=5055)
	sub.add_parser('stop')
	args = p.parse_args()
	if args.action == 'start':
		start(args.host, args.port)
	elif args.action == 'stop':
		try:
			pid = int(open(PID_FILE).read().strip()); os.kill(pid, 15); os.remove(PID_FILE); print(json.dumps({'success': True}))
		except Exception as e:
			print(json.dumps({'success': False, 'error': str(e)})) 