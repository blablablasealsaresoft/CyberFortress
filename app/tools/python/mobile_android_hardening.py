#!/usr/bin/env python3
import argparse, json, shutil, subprocess, re


def have_adb():
	return shutil.which('adb') is not None

def run_adb(serial, args):
	cmd = ['adb']
	if serial:
		cmd += ['-s', serial]
	cmd += args
	try:
		out = subprocess.check_output(cmd, text=True, stderr=subprocess.STDOUT)
		return 0, out
	except subprocess.CalledProcessError as e:
		return e.returncode, e.output


def get_prop(serial, ns, key):
	code, out = run_adb(serial, ['shell', 'settings', 'get', ns, key])
	return (out or '').strip()

def put_prop(serial, ns, key, value):
	code, out = run_adb(serial, ['shell', 'settings', 'put', ns, key, value])
	return code == 0


def audit(serial):
	info = {
		'adb_enabled': get_prop(serial, 'global', 'adb_enabled'),
		'install_non_market_apps': get_prop(serial, 'secure', 'install_non_market_apps'),
		'package_verifier_enable': get_prop(serial, 'global', 'package_verifier_enable'),
		'verifier_verify_adb_installs': get_prop(serial, 'global', 'verifier_verify_adb_installs'),
		'wifi_scan_always_enabled': get_prop(serial, 'global', 'wifi_scan_always_enabled'),
		'ble_scan_always_enabled': get_prop(serial, 'global', 'ble_scan_always_enabled'),
		'lock_screen_allow_private_notifications': get_prop(serial, 'secure', 'lock_screen_allow_private_notifications'),
		'lock_screen_show_notifications': get_prop(serial, 'secure', 'lock_screen_show_notifications'),
	}
	return info


def apply(serial):
	changes = {
		'adb_enabled': put_prop(serial, 'global', 'adb_enabled', '0'),
		'package_verifier_enable': put_prop(serial, 'global', 'package_verifier_enable', '1'),
		'verifier_verify_adb_installs': put_prop(serial, 'global', 'verifier_verify_adb_installs', '1'),
		'wifi_scan_always_enabled': put_prop(serial, 'global', 'wifi_scan_always_enabled', '0'),
		'ble_scan_always_enabled': put_prop(serial, 'global', 'ble_scan_always_enabled', '0'),
	}
	# Attempt to disable installing from unknown sources (older APIs)
	_ = put_prop(serial, 'secure', 'install_non_market_apps', '0')
	return changes


def freeze(serial, package):
	code, out = run_adb(serial, ['shell', 'pm', 'disable-user', '--user', '0', package])
	return code == 0, out

def unfreeze(serial, package):
	code, out = run_adb(serial, ['shell', 'pm', 'enable', package])
	return code == 0, out


def list_dangerous(serial, package):
	code, out = run_adb(serial, ['shell', 'dumpsys', 'package', package])
	perms = []
	if code == 0:
		for line in out.splitlines():
			line = line.strip()
			if 'granted=true' in line and 'dangerous' in line:
				m = re.search(r'name=(\S+)', line)
				if m: perms.append(m.group(1))
	return perms


def revoke_dangerous(serial, package):
	perms = list_dangerous(serial, package)
	results = []
	for perm in perms:
		code, out = run_adb(serial, ['shell', 'pm', 'revoke', package, perm])
		results.append({'permission': perm, 'success': code == 0})
	return results


def set_policy(serial, namespace, key, value):
	ok = put_prop(serial, namespace, key, value)
	return ok

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--serial')
	sub = p.add_subparsers(dest='action', required=True)
	sub.add_parser('audit')
	sub.add_parser('apply')
	fz = sub.add_parser('freeze'); fz.add_argument('--package', required=True)
	uf = sub.add_parser('unfreeze'); uf.add_argument('--package', required=True)
	rd = sub.add_parser('revoke-dangerous'); rd.add_argument('--package', required=True)
	sp = sub.add_parser('set-policy'); sp.add_argument('--ns', choices=['system','secure','global'], required=True); sp.add_argument('--key', required=True); sp.add_argument('--value', required=True)
	args = p.parse_args()

	if not have_adb():
		print(json.dumps({'success': False, 'error': 'adb_not_found'})); raise SystemExit(0)

	if args.action == 'audit':
		print(json.dumps({'success': True, 'audit': audit(args.serial)}))
	elif args.action == 'apply':
		print(json.dumps({'success': True, 'changes': apply(args.serial)}))
	elif args.action == 'freeze':
		s, out = freeze(args.serial, args.package)
		print(json.dumps({'success': s, 'output': out}))
	elif args.action == 'unfreeze':
		s, out = unfreeze(args.serial, args.package)
		print(json.dumps({'success': s, 'output': out}))
	elif args.action == 'revoke-dangerous':
		print(json.dumps({'success': True, 'results': revoke_dangerous(args.serial, args.package)}))
	elif args.action == 'set-policy':
		print(json.dumps({'success': set_policy(args.serial, args.ns, args.key, args.value)})) 