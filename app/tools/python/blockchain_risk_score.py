#!/usr/bin/env python3
import argparse, json

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--vulns', type=int, default=0)
	p.add_argument('--critical', type=int, default=0)
	p.add_argument('--ownership', type=int, default=50)
	p.add_argument('--liquidity', type=int, default=50)
	p.add_argument('--history', type=int, default=50)
	p.add_argument('--social', type=int, default=50)
	p.add_argument('--audits', type=int, default=50)
	args = p.parse_args()
	# Simple weighted scoring (higher is safer here); convert to risk by 100 - score
	score = 0
	score += max(0, 100 - (args.critical*30 + args.vulns*5)) * 0.25
	score += args.ownership * 0.20
	score += args.liquidity * 0.20
	score += args.history * 0.15
	score += args.social * 0.10
	score += args.audits * 0.10
	risk = max(0, 100 - int(score))
	level = 'LOW'
	if risk >= 75: level = 'CRITICAL'
	elif risk >= 50: level = 'HIGH'
	elif risk >= 25: level = 'MEDIUM'
	print(json.dumps({'risk': risk, 'level': level, 'score': int(score)})) 