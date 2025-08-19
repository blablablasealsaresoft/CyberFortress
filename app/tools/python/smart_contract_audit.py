#!/usr/bin/env python3
import argparse, json, os, subprocess, shutil


def run_cmd(cmd):
	try:
		out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
		return 0, out
	except subprocess.CalledProcessError as e:
		return e.returncode, e.output

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--target', required=True, help='Path to a Solidity project or file')
	args = p.parse_args()
	report = {'slither': None, 'mythril': None, 'echidna': None, 'manticore': None}
	if shutil.which('slither'):
		code, out = run_cmd(['slither', args.target, '--json', 'report.json'])
		report['slither'] = out[-2000:]
	if shutil.which('myth'):
		code, out = run_cmd(['myth', 'analyze', args.target, '-o', 'json'])
		report['mythril'] = out[-2000:]
	if shutil.which('echidna-test'):
		code, out = run_cmd(['echidna-test', args.target, '--test-mode', 'assertion'])
		report['echidna'] = out[-2000:]
	if shutil.which('manticore'):
		code, out = run_cmd(['manticore', args.target])
		report['manticore'] = out[-2000:]
	print(json.dumps({'success': True, 'report': report})) 