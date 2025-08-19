#!/usr/bin/env python3
import argparse
import time
import subprocess
from datetime import datetime, timedelta
from typing import List, Dict
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib


MODEL_PATH = 'firewall_ml_model.pkl'
SCALER_PATH = 'firewall_scaler.pkl'


def collect_traffic_data(duration_minutes: int = 10) -> pd.DataFrame:
	print(f"Collecting traffic for {duration_minutes} minutes...")
	end_time = datetime.now() + timedelta(minutes=duration_minutes)
	rows: List[Dict] = []
	while datetime.now() < end_time:
		try:
			output = subprocess.check_output(['ss', '-tunap'], text=True)
			for line in output.splitlines()[1:]:
				parts = line.split()
				if len(parts) >= 5 and 'State' not in line:
					proto = parts[0]
					local = parts[3]
					remote = parts[4]
					if ':' in local and ':' in remote:
						try:
							local_port = int(local.rsplit(':', 1)[-1])
							remote_ip = remote.rsplit(':', 1)[0]
							remote_port = int(remote.rsplit(':', 1)[-1])
							rows.append({
								'timestamp': datetime.now(),
								'protocol': proto,
								'local_port': local_port,
								'remote_ip': remote_ip,
								'remote_port': remote_port
							})
						except Exception:
							continue
		except Exception:
			pass
		time.sleep(5)
	return pd.DataFrame(rows)


def extract_features(df: pd.DataFrame) -> np.ndarray:
	features = []
	for ip in df['remote_ip'].unique():
		ip_data = df[df['remote_ip'] == ip]
		features.append([
			len(ip_data),
			ip_data['local_port'].nunique(),
			ip_data['remote_port'].nunique(),
			(int((ip_data['timestamp'].max() - ip_data['timestamp'].min()).total_seconds()) if len(ip_data) else 0),
			len(ip_data[ip_data['protocol'] == 'tcp']) / max(len(ip_data), 1),
			len(ip_data[ip_data['remote_port'] < 1024]) / max(len(ip_data), 1),
		])
	return np.array(features)


def train_model(minutes: int) -> None:
	df = collect_traffic_data(minutes)
	if df.empty:
		print('No data collected; aborting training')
		return
	X = extract_features(df)
	scaler = StandardScaler()
	X_scaled = scaler.fit_transform(X)
	model = IsolationForest(contamination=0.1, random_state=42)
	model.fit(X_scaled)
	joblib.dump(model, MODEL_PATH)
	joblib.dump(scaler, SCALER_PATH)
	print('Model trained and saved')


def detect_and_generate(minutes: int, apply: bool) -> List[str]:
	df = collect_traffic_data(minutes)
	if df.empty:
		print('No data collected; nothing to detect')
		return []
	model = joblib.load(MODEL_PATH)
	scaler = joblib.load(SCALER_PATH)
	X = extract_features(df)
	X_scaled = scaler.transform(X)
	pred = model.predict(X_scaled)
	anomalous_ips = [ip for ip, y in zip(df['remote_ip'].unique(), pred) if y == -1]
	rules = []
	for ip in anomalous_ips:
		rules.append(f"iptables -A INPUT -s {ip} -j DROP")
		rules.append(f"nft add rule inet filter input ip saddr {ip} drop")
		if apply:
			subprocess.call(['sh', '-c', f"iptables -A INPUT -s {ip} -j DROP"]) 
			# nft may not be present; best-effort
			subprocess.call(['sh', '-c', f"nft add rule inet filter input ip saddr {ip} drop"], stderr=subprocess.DEVNULL)
	print('\n'.join(rules))
	return rules


def adaptive_loop() -> None:
	while True:
		try:
			_ = detect_and_generate(minutes=10, apply=True)
		except Exception:
			pass
		time.sleep(600)


def main() -> None:
	parser = argparse.ArgumentParser(description='ML-based firewall rule generator')
	sub = parser.add_subparsers(dest='cmd', required=True)
	p_train = sub.add_parser('train')
	p_train.add_argument('--minutes', type=int, default=60)
	p_detect = sub.add_parser('detect')
	p_detect.add_argument('--minutes', type=int, default=10)
	p_detect.add_argument('--apply', action='store_true')
	p_adaptive = sub.add_parser('adaptive')
	args = parser.parse_args()
	if args.cmd == 'train':
		train_model(args.minutes)
	elif args.cmd == 'detect':
		detect_and_generate(args.minutes, bool(args.apply))
	else:
		adaptive_loop()


if __name__ == '__main__':
	main() 