#!/usr/bin/env python3
from flask import Flask, request, jsonify, send_file
import os, io, base64, secrets, json
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import qrcode
from pathlib import Path

app = Flask(__name__)
STORE = Path('./encrypted_files'); STORE.mkdir(exist_ok=True)
META = STORE / 'metadata.json'
metadata = json.load(open(META,'r')) if META.exists() else {}


def derive_key(password: str, salt: bytes) -> bytes:
	kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=200000, backend=default_backend())
	return kdf.derive(password.encode())


@app.post('/upload')
def upload():
	if 'file' not in request.files:
		return jsonify({'error':'file required'}), 400
	f = request.files['file']
	password = request.form.get('password') or secrets.token_urlsafe(32)
	pt = f.read()
	salt = os.urandom(32)
	key = derive_key(password, salt)
	iv = os.urandom(16)
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	encryptor = cipher.encryptor()
	pad = 16 - (len(pt) % 16)
	ct = encryptor.update(pt + bytes([pad])*pad) + encryptor.finalize()
	fid = secrets.token_urlsafe(12)
	mac = hashes.Hash(hashes.SHA256(), backend=default_backend())
	mac.update(ct)
	encrypted_path = STORE / f"{fid}.enc"
	with open(encrypted_path, 'wb') as out:
		out.write(salt + iv + mac.finalize() + ct)
	metadata[fid] = {
		'original_name': f.filename,
		'upload_time': datetime.utcnow().isoformat(),
		'expires': (datetime.utcnow()+timedelta(days=7)).isoformat(),
		'downloads': 0,
		'max_downloads': 5
	}
	json.dump(metadata, open(META,'w'))
	qr = qrcode.make(f"/download/{fid}#{password}")
	buf = io.BytesIO(); qr.save(buf, format='PNG'); buf.seek(0)
	return jsonify({'file_id': fid, 'password': password, 'qr_png_b64': base64.b64encode(buf.read()).decode()})


@app.post('/download/<fid>')
def download(fid: str):
	password = request.json.get('password')
	if not password:
		return jsonify({'error':'password required'}), 400
	if fid not in metadata:
		return jsonify({'error':'not found'}), 404
	meta = metadata[fid]
	if datetime.fromisoformat(meta['expires']) < datetime.utcnow():
		return jsonify({'error':'expired'}), 404
	path = STORE / f"{fid}.enc"
	enc = open(path,'rb').read()
	salt, iv, mac, ct = enc[:32], enc[32:48], enc[48:80], enc[80:]
	key = derive_key(password, salt)
	cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
	pt = cipher.decryptor().update(ct) + cipher.decryptor().finalize()
	pad = pt[-1]; pt = pt[:-pad]
	metadata[fid]['downloads'] += 1
	json.dump(metadata, open(META,'w'))
	return send_file(io.BytesIO(pt), as_attachment=True, download_name=meta.get('original_name','download'))


if __name__ == '__main__':
	app.run(host='0.0.0.0', port=5001) 