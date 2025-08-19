#!/usr/bin/env python3
import time, psutil, socket, ssl, subprocess, json
from datetime import datetime

def is_encrypted_port(port: int) -> bool:
	return port in {443,22,993,995,465,587,8443,9001}

def get_process(pid):
	try:
		return psutil.Process(pid).name()
	except: return 'unknown'

def monitor_connections(iterations: int = 12, sleep_s: int = 5):
	alerts = []
	for _ in range(iterations):
		for conn in psutil.net_connections():
			if conn.status == psutil.CONN_ESTABLISHED and conn.raddr:
				lport = conn.laddr.port if conn.laddr else 0
				if not is_encrypted_port(lport):
					alerts.append({'type':'unencrypted_connection','local': f"{conn.laddr.ip}:{lport}", 'remote': f"{conn.raddr.ip}:{conn.raddr.port}", 'process': get_process(conn.pid), 'ts': datetime.utcnow().isoformat()})
		time.sleep(sleep_s)
	return alerts

def check_dns_security():
	try:
		resolv = open('/etc/resolv.conf').read()
		secure_dns = ['1.1.1.1','9.9.9.9','8.8.8.8']
		return any(x in resolv for x in secure_dns)
	except: return False

def check_cert_expiry(hostname: str, port: int = 443) -> int:
	try:
		ctx = ssl.create_default_context();
		with socket.create_connection((hostname, port), timeout=5) as sock:
			with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
				cert = ssock.getpeercert();
				not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
				return (not_after - datetime.utcnow()).days
	except: return -1

if __name__ == '__main__':
	result = {
		'alerts': monitor_connections(),
		'dns_secure': check_dns_security(),
		'cert_days_left': {h: check_cert_expiry(h) for h in ['github.com','cloudflare.com','google.com']}
	}
	print(json.dumps(result)) 