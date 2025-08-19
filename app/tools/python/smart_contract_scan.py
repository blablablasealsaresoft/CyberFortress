#!/usr/bin/env python3
import argparse
import json
import os
import re
import subprocess
from typing import List


def run_cmd(cmd: List[str]) -> str:
	try:
		return subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
	except Exception as e:
		return str(e)


def analyze_with_slither(target: str) -> str:
	return run_cmd(['slither', target, '--detect', 'all'])

def analyze_with_mythril(target: str) -> str:
	return run_cmd(['myth', 'analyze', target, '-o', 'json'])


def simple_heuristics(source: str) -> List[str]:
	vuln_patterns = {
		'reentrancy': r'call\.value\(.*\)\(\)',
		'unchecked_call': r'call\(\)(?!.*require)',
		'integer_overflow': r'[\+\-\*](?!.*SafeMath)'
	}
	findings = []
	try:
		text = open(source,'r',encoding='utf-8',errors='ignore').read()
		for name,pat in vuln_patterns.items():
			if re.search(pat, text):
				findings.append(name)
	except Exception:
		pass
	return findings


def main():
	p = argparse.ArgumentParser(description='Smart contract analyzer')
	p.add_argument('target', help='Solidity file or bytecode path')
	args = p.parse_args()
	result = {"tool":"heuristics","findings": simple_heuristics(args.target)}
	if shutil.which('slither'):
		result = {"tool":"slither","output": analyze_with_slither(args.target)}
	elif shutil.which('myth'):
		result = {"tool":"mythril","output": analyze_with_mythril(args.target)}
	print(json.dumps(result))

if __name__ == '__main__':
	import shutil
	main() 