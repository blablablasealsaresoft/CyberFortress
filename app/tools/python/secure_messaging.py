#!/usr/bin/env python3
import argparse
import asyncio
import ssl
import json
import base64
from datetime import datetime
import websockets

USERS = {}
PENDING = {}

async def handle_client(ws):
	try:
		async for raw in ws:
			msg = json.loads(raw)
			t = msg.get('type')
			if t == 'register':
				uid = msg['user_id']
				USERS[uid] = ws
				if uid in PENDING:
					for m in PENDING[uid]:
						await ws.send(json.dumps(m))
					PENDING.pop(uid, None)
				await ws.send(json.dumps({'type':'registered','user_id':uid,'timestamp':datetime.utcnow().isoformat()}))
			elif t == 'message':
				recipient = msg['recipient']
				payload = {'type':'message','sender':msg['sender'],'content':msg['encrypted_content'],'ts':datetime.utcnow().isoformat()}
				rws = USERS.get(recipient)
				if rws:
					await rws.send(json.dumps(payload))
				else:
					PENDING.setdefault(recipient, []).append(payload)
			elif t == 'key_exchange':
				recipient = msg['recipient']
				payload = {'type':'key_exchange','sender':msg.get('sender'), 'dh_public': msg.get('dh_public'), 'ts': datetime.utcnow().isoformat()}
				rws = USERS.get(recipient)
				if rws:
					await rws.send(json.dumps(payload))
				else:
					PENDING.setdefault(recipient, []).append(payload)
	except websockets.exceptions.ConnectionClosed:
		pass

async def start_server(host: str, port: int, cert: str, key: str):
	ssl_ctx = None
	if cert and key:
		ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
		ssl_ctx.load_cert_chain(cert, keyfile=key)
	server = await websockets.serve(handle_client, host, port, ssl=ssl_ctx)
	print(f"Secure messaging relay on {'wss' if ssl_ctx else 'ws'}://{host}:{port}")
	await server.wait_closed()


def main():
	p = argparse.ArgumentParser(description='Secure messaging relay (transport)')
	p.add_argument('--host', default='0.0.0.0')
	p.add_argument('--port', type=int, default=8765)
	p.add_argument('--cert')
	p.add_argument('--key')
	args = p.parse_args()
	asyncio.run(start_server(args.host, args.port, args.cert, args.key))

if __name__ == '__main__':
	main() 