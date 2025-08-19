#!/usr/bin/env python3
import argparse, json

def analyze(tx_json: str):
	Tx = json.loads(tx_json)
	value = int(Tx.get('value', 0))
	gwei = int(Tx.get('gasPrice', 0)) // (10**9)
	is_swap = (Tx.get('to','') or '').lower() in ['uniswap', 'router', 'sushiswap'] or 'swap' in (Tx.get('data','') or '').lower()
	risk = 0.0
	if is_swap: risk += 0.4
	if value > 10**20: risk += 0.3
	if gwei > 150: risk += 0.2
	rec = {
		'private_mempool': risk >= 0.5,
		'recommended_slippage_bps': 50 if risk >= 0.5 else 100
	}
	return {'risk_score': risk, 'recommendation': rec}

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--tx', required=True)
	args = p.parse_args()
	print(json.dumps(analyze(args.tx))) 