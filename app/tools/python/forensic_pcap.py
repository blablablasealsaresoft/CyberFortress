#!/usr/bin/env python3
import argparse, json, os, subprocess, time, signal

RUNTIME = os.path.join(os.path.dirname(__file__), '../../data/runtime')
os.makedirs(RUNTIME, exist_ok=True)
PID_FILE = os.path.join(RUNTIME, 'pcap_capture.pid')

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest='action', required=True)
	st = sub.add_parser('start'); st.add_argument('--iface', default='eth0'); st.add_argument('--out', default='capture.pcapng')
	sub.add_parser('stop')
	args = p.parse_args()
	if args.action == 'start':
		out = args.out if os.path.isabs(args.out) else os.path.abspath(args.out)
		cmd = ['tshark','-i', args.iface, '-w', out]
		try:
			proc = subprocess.Popen(cmd)
			open(PID_FILE,'w').write(str(proc.pid))
			print(json.dumps({"success": True, "pid": proc.pid, "out": out}))
		except Exception as e:
			print(json.dumps({"success": False, "error": str(e)}))
	elif args.action == 'stop':
		try:
			pid = int(open(PID_FILE).read().strip())
			os.kill(pid, signal.SIGTERM)
			os.remove(PID_FILE)
			print(json.dumps({"success": True}))
		except Exception as e:
			print(json.dumps({"success": False, "error": str(e)})) 