#!/usr/bin/env python3
import argparse, json

def score(data: dict):
	risk = 0
	ownership = data.get('ownership',{})
	liquidity = data.get('liquidity',{})
	code = data.get('code',{})
	if not ownership.get('renounced'): risk += 15
	if not ownership.get('multisig'): risk += 10
	if not ownership.get('timelocked'): risk += 10
	if liquidity.get('locked_percent',0) < 80: risk += 10
	if liquidity.get('lock_days',0) < 365: risk += 10
	if code.get('mint_function'): risk += 5
	if code.get('blacklist'): risk += 5
	if code.get('hidden_fees'): risk += 5
	if code.get('honeypot'): risk += 20
	level = 'LOW'
	if risk >= 60: level = 'CRITICAL'
	elif risk >= 40: level = 'HIGH'
	elif risk >= 20: level = 'MEDIUM'
	return {'risk_score': risk, 'level': level}

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--features', required=True, help='JSON with ownership/liquidity/code')
	args = p.parse_args()
	print(json.dumps(score(json.loads(args.features)))) 