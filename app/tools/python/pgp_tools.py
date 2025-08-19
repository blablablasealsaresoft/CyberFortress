#!/usr/bin/env python3
import argparse, json, subprocess, os

GPG = os.environ.get('GPG_BIN','gpg')

def run(cmd):
	return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest='action', required=True)
	kg = sub.add_parser('keygen'); kg.add_argument('--name', required=True); kg.add_argument('--email', required=True)
	e = sub.add_parser('encrypt'); e.add_argument('--recipient', required=True); e.add_argument('--in', dest='inp', required=True); e.add_argument('--out', required=True)
	d = sub.add_parser('decrypt'); d.add_argument('--in', dest='inp', required=True); d.add_argument('--out', required=True)
	args = p.parse_args()
	if args.action == 'keygen':
		cmd = [GPG,'--batch','--pinentry-mode','loopback','--quick-generate-key',f"{args.name} <{args.email}>", 'default', 'default', 'never']
		res = run(cmd); print(json.dumps({"success": res.returncode==0, "out": res.stdout[-1000:], "err": res.stderr[-1000:]}))
	elif args.action == 'encrypt':
		res = run([GPG,'--yes','--output',args.out,'--encrypt','--recipient',args.recipient,args.inp]); print(json.dumps({"success": res.returncode==0, "out": res.stdout[-1000:], "err": res.stderr[-1000:]}))
	elif args.action == 'decrypt':
		res = run([GPG,'--yes','--output',args.out,'--decrypt',args.inp]); print(json.dumps({"success": res.returncode==0, "out": res.stdout[-1000:], "err": res.stderr[-1000:]})) 