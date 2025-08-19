#!/usr/bin/env python3
import argparse, json

def detect(features: dict):
	checks = {
		'can_sell': bool(features.get('can_sell', True)),
		'hidden_fees_bps': int(features.get('hidden_fees_bps', 0)),
		'blacklist': bool(features.get('blacklist', False)),
		'pausable': bool(features.get('pausable', False)),
		'modifiable_fees': bool(features.get('modifiable_fees', False)),
		'cooldown': bool(features.get('cooldown', False)),
		'max_tx_limit': bool(features.get('max_tx_limit', False)),
	}
	is_honeypot = (not checks['can_sell']) or (checks['hidden_fees_bps'] > 500) or (checks['blacklist'] and checks['modifiable_fees'])
	risk = 0
	if not checks['can_sell']: risk += 60
	if checks['hidden_fees_bps'] > 500: risk += 30
	if checks['blacklist']: risk += 10
	if checks['pausable']: risk += 5
	if checks['modifiable_fees']: risk += 10
	if checks['cooldown']: risk += 5
	if checks['max_tx_limit']: risk += 10
	return {'is_honeypot': is_honeypot, 'risk': min(100, risk), 'details': checks}

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--features', required=True)
	args = p.parse_args()
	print(json.dumps(detect(json.loads(args.features)))) 