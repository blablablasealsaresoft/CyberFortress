#!/usr/bin/env python3
import argparse, json, time, requests

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest='action', required=True)
	mon = sub.add_parser('monitor'); mon.add_argument('--address', required=True); mon.add_argument('--webhook', required=False)
	al = sub.add_parser('alert'); al.add_argument('--channel', choices=['WEBHOOK','EMAIL'], required=True); al.add_argument('--target', required=True); al.add_argument('--message', required=True)
	er = sub.add_parser('emergency'); er.add_argument('--action', choices=['BLOCK_ALL','DISCONNECT_WALLET','REVOKE_APPROVALS'], required=True)
	args = p.parse_args()
	if args.action == 'monitor':
		alert = {'level':'CRITICAL','contract':args.address,'event':'OwnershipTransferred','timestamp':int(time.time())}
		if args.webhook:
			try:
				requests.post(args.webhook, json=alert, timeout=10)
			except Exception:
				pass
		print(json.dumps({'success': True, 'alert': alert}))
	elif args.action == 'alert':
		print(json.dumps({'success': True, 'channel': args.channel, 'target': args.target, 'message': args.message}))
	elif args.action == 'emergency':
		print(json.dumps({'success': True, 'performed': args.action})) 