#!/usr/bin/env python3
import argparse, json, platform, subprocess

if platform.system().lower() != 'windows':
	print(json.dumps({"success": False, "error": "windows_only"}))
	exit(0)

try:
	import winreg
except Exception:
	winreg = None


def reg_set(path, name, val, typ):
	if not winreg: return False
	root, sub = path.split('\\', 1)
	root_key = getattr(winreg, root)
	key = winreg.CreateKeyEx(root_key, sub, 0, winreg.KEY_SET_VALUE)
	winreg.SetValueEx(key, name, 0, typ, val)
	winreg.CloseKey(key)
	return True


def disable_telemetry():
	ok = True
	ok &= reg_set('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection','AllowTelemetry', 0, winreg.REG_DWORD)
	ok &= reg_set('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\DataCollection','DisableTelemetry', 1, winreg.REG_DWORD)
	ok &= reg_set('HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\AdvertisingInfo','Disabled', 1, winreg.REG_DWORD)
	# Disable services (best-effort)
	subprocess.call(['sc','stop','DiagTrack'])
	subprocess.call(['sc','config','DiagTrack','start=','disabled'])
	subprocess.call(['sc','stop','dmwappushservice'])
	subprocess.call(['sc','config','dmwappushservice','start=','disabled'])
	return ok

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest='action', required=True)
	sub.add_parser('disable-telemetry')
	args = p.parse_args()
	if args.action == 'disable-telemetry':
		print(json.dumps({"success": disable_telemetry()})) 