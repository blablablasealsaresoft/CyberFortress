#!/usr/bin/env python3
import argparse
import json
import os
import paramiko
import shlex
from typing import Optional


def ssh_connect(host: str, user: str, password: Optional[str], keyfile: Optional[str]) -> paramiko.SSHClient:
	client = paramiko.SSHClient()
	client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
	if keyfile:
		pkey = paramiko.RSAKey.from_private_key_file(keyfile)
		client.connect(hostname=host, username=user, pkey=pkey, timeout=30)
	else:
		client.connect(hostname=host, username=user, password=password, timeout=30)
	return client


def run_script(client: paramiko.SSHClient, script: str) -> str:
	stdin, stdout, stderr = client.exec_command("bash -lc " + shlex.quote(script))
	out = stdout.read().decode('utf-8', errors='ignore')
	err = stderr.read().decode('utf-8', errors='ignore')
	return out + ("\n" + err if err else '')


def deploy(host: str, user: str, password: Optional[str], keyfile: Optional[str], domain: str, email: str, turn_secret: str) -> dict:
	client = ssh_connect(host, user, password, keyfile)
	try:
		script = """
		set -e
		export DEBIAN_FRONTEND=noninteractive
		sudo apt-get update -y
		sudo apt-get install -y matrix-synapse-py3 coturn nginx certbot python3-certbot-nginx jq
		# matrix basic config
		if [ ! -f /etc/matrix-synapse/homeserver.yaml ]; then
			sudo /usr/bin/matrix-synapse --generate-config -H __DOMAIN__
		fi
		sudo sed -i 's/^#*\s*server_name:.*/server_name: __DOMAIN__/' /etc/matrix-synapse/homeserver.yaml || true
		# enable registration shared secret
		if ! grep -q '^registration_shared_secret:' /etc/matrix-synapse/homeserver.yaml; then
			echo 'registration_shared_secret: '$(head -c 32 /dev/urandom | xxd -p) | sudo tee -a /etc/matrix-synapse/homeserver.yaml >/dev/null
		fi
		# nginx for matrix well-known and reverse proxy
		cat <<'NGX' | sudo tee /etc/nginx/sites-available/matrix >/dev/null
		server {
			listen 80;
			server_name __DOMAIN__;
			location /.well-known/matrix/server { return 200 '{"m.server": "__DOMAIN__:443"}'; add_header Content-Type application/json; }
			location /.well-known/matrix/client { return 200 '{"m.homeserver": {"base_url": "https://__DOMAIN__"}}'; add_header Access-Control-Allow-Origin *; add_header Content-Type application/json; }
			location /_matrix { proxy_pass http://127.0.0.1:8008; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header Host $host; }
		}
		NGX
		sudo ln -sf /etc/nginx/sites-available/matrix /etc/nginx/sites-enabled/matrix
		sudo rm -f /etc/nginx/sites-enabled/default || true
		sudo nginx -t
		sudo systemctl restart nginx
		# TLS
		sudo certbot --nginx -d __DOMAIN__ --non-interactive --agree-tos -m __EMAIL__ || true
		# coturn config
		sudo sed -i 's/^#*TURNSERVER_ENABLED=.*/TURNSERVER_ENABLED=1/' /etc/default/coturn || true
		sudo bash -lc 'grep -q "use-auth-secret" /etc/turnserver.conf || echo use-auth-secret >> /etc/turnserver.conf'
		sudo bash -lc 'grep -q "static-auth-secret" /etc/turnserver.conf && sed -i "s/^static-auth-secret.*/static-auth-secret=__TURN_SECRET__/" /etc/turnserver.conf || echo static-auth-secret=__TURN_SECRET__ >> /etc/turnserver.conf'
		sudo bash -lc 'grep -q "realm" /etc/turnserver.conf && sed -i "s/^realm.*/realm=__DOMAIN__/" /etc/turnserver.conf || echo realm=__DOMAIN__ >> /etc/turnserver.conf'
		sudo bash -lc 'grep -q "no-loopback-peers" /etc/turnserver.conf || echo no-loopback-peers >> /etc/turnserver.conf'
		sudo bash -lc 'grep -q "no-multicast-peers" /etc/turnserver.conf || echo no-multicast-peers >> /etc/turnserver.conf'
		# synapse turn config fragment
		sudo mkdir -p /etc/matrix-synapse/conf.d
		cat <<'YAML' | sudo tee /etc/matrix-synapse/conf.d/turn.yml >/dev/null
		turn_uris: [ "turn:__DOMAIN__:3478?transport=udp", "turn:__DOMAIN__:3478?transport=tcp" ]
		turn_shared_secret: "__TURN_SECRET__"
		turn_user_lifetime: 86400000
		YAML
		# restart services
		sudo systemctl enable --now matrix-synapse
		sudo systemctl enable --now coturn
		sudo systemctl restart matrix-synapse || true
		sudo systemctl restart coturn || true
		echo DEPLOY_OK
		""".replace("__DOMAIN__", domain).replace("__EMAIL__", email).replace("__TURN_SECRET__", turn_secret)
		res = run_script(client, script)
		ok = 'DEPLOY_OK' in res
		return {
			'success': ok,
			'output': res[-2000:],
			'endpoints': {
				'matrix_base_url': f'https://{domain}',
				'matrix_federation': f'{domain}:443',
				'turn': f'turn:{domain}:3478'
			}
		}
	finally:
		client.close()


def status(host: str, user: str, password: Optional[str], keyfile: Optional[str]) -> dict:
	client = ssh_connect(host, user, password, keyfile)
	try:
		script = """
		matrix=$(systemctl is-active matrix-synapse || true)
		turn=$(systemctl is-active coturn || true)
		nginx=$(systemctl is-active nginx || true)
		echo "MATRIX=$matrix TURN=$turn NGINX=$nginx"
		"""
		res = run_script(client, script)
		return {
			'matrix': 'active' in res,
			'turn': 'TURN=active' in res,
			'nginx': 'NGINX=active' in res,
			'raw': res.strip()[:2000]
		}
	finally:
		client.close()


def destroy(host: str, user: str, password: Optional[str], keyfile: Optional[str]) -> dict:
	client = ssh_connect(host, user, password, keyfile)
	try:
		script = """
		sudo systemctl disable --now matrix-synapse || true
		sudo systemctl disable --now coturn || true
		sudo apt-get purge -y matrix-synapse-py3 coturn || true
		sudo rm -rf /etc/matrix-synapse /var/lib/matrix-synapse || true
		sudo rm -f /etc/nginx/sites-enabled/matrix /etc/nginx/sites-available/matrix || true
		sudo systemctl restart nginx || true
		echo DESTROY_OK
		"""
		res = run_script(client, script)
		return {'success': 'DESTROY_OK' in res, 'output': res[-2000:]}
	finally:
		client.close()


if __name__ == '__main__':
	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest='action', required=True)
	common = argparse.ArgumentParser(add_help=False)
	common.add_argument('--host', required=True)
	common.add_argument('--user', required=True)
	cred = common.add_mutually_exclusive_group(required=False)
	cred.add_argument('--password')
	cred.add_argument('--keyfile')
	# deploy
	pd = sub.add_parser('deploy', parents=[common])
	pd.add_argument('--domain', required=True)
	pd.add_argument('--email', required=True)
	pd.add_argument('--turn-secret', required=True)
	# status
	sub.add_parser('status', parents=[common])
	# destroy
	sub.add_parser('destroy', parents=[common])
	args = p.parse_args()

	if args.action == 'deploy':
		print(json.dumps(deploy(args.host, args.user, getattr(args, 'password', None), getattr(args, 'keyfile', None), args.domain, args.email, args.__dict__['turn_secret'])))
	elif args.action == 'status':
		print(json.dumps(status(args.host, args.user, getattr(args, 'password', None), getattr(args, 'keyfile', None))))
	elif args.action == 'destroy':
		print(json.dumps(destroy(args.host, args.user, getattr(args, 'password', None), getattr(args, 'keyfile', None)))) 