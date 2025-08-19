#!/usr/bin/env python3
import argparse, json, os, time, uuid, yaml, hashlib, random
from datetime import datetime

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/annotation'))
SCHEMA = os.path.join(BASE, 'annotation_schema.yaml')
ANNOTATIONS = os.path.join(BASE, 'annotations.jsonl')
SAMPLES = os.path.join(BASE, 'samples.jsonl')

os.makedirs(BASE, exist_ok=True)

DEFAULT_SCHEMA = {
	'annotation_schema': {
		'version': '1.0.0',
		'threat_levels': [
			{'id':'critical','name':'Critical Threat','sla_response':'< 5 minutes'},
			{'id':'high','name':'High Threat','sla_response':'< 30 minutes'},
			{'id':'medium','name':'Medium Threat','sla_response':'< 4 hours'},
			{'id':'low','name':'Low Threat','sla_response':'< 24 hours'},
			{'id':'benign','name':'Benign/Normal','sla_response':'N/A'},
		],
		'attack_types': {
			'network': ['ddos','port_scanning','packet_injection','man_in_the_middle','dns_poisoning'],
			'application': ['sql_injection','xss','csrf','command_injection','path_traversal'],
			'authentication': ['brute_force','credential_stuffing','session_hijacking','privilege_escalation','password_spraying'],
			'malware': ['ransomware','trojan','worm','rootkit','spyware'],
			'data': ['exfiltration','unauthorized_access','data_tampering','information_disclosure','privacy_violation']
		},
		'confidence_scores': [
			{'value':1.0,'label':'Certain'},
			{'value':0.8,'label':'High Confidence'},
			{'value':0.6,'label':'Moderate Confidence'},
			{'value':0.4,'label':'Low Confidence'},
			{'value':0.2,'label':'Uncertain'},
		]
	}
}


def schema_init():
	if not os.path.exists(SCHEMA):
		with open(SCHEMA,'w') as f:
			yaml.dump(DEFAULT_SCHEMA, f)
	return True

def schema_get():
	if not os.path.exists(SCHEMA):
		schema_init()
	return yaml.safe_load(open(SCHEMA,'r'))


def get_batch(batch_size: int = 10):
	# Generate mock samples if SAMPLES empty
	if not os.path.exists(SAMPLES) or os.path.getsize(SAMPLES) == 0:
		with open(SAMPLES,'a') as f:
			for _ in range(100):
				sample = {
					'id': f'sample_{uuid.uuid4().hex[:8]}',
					'timestamp': datetime.utcnow().isoformat(),
					'source_ip': f'192.168.{random.randint(0,255)}.{random.randint(0,255)}',
					'destination_ip': f'10.0.{random.randint(0,255)}.{random.randint(0,255)}',
					'protocol': random.choice(['TCP','UDP','HTTP','HTTPS']),
					'payload': hashlib.sha256(os.urandom(16)).hexdigest(),
				}
				f.write(json.dumps(sample)+'\n')
	items = []
	with open(SAMPLES,'r') as f:
		for idx, line in enumerate(f):
			if idx >= batch_size: break
			items.append(json.loads(line))
	return {'batch_id': uuid.uuid4().hex, 'samples': items, 'schema': schema_get()}


def submit_annotation(annotation: dict):
	required = ['annotator_id','sample_id','labels','confidence']
	for r in required:
		if r not in annotation:
			return {'success': False, 'error': f'missing_{r}'}
	# Simple validation against threat levels
	levels = [x['id'] for x in schema_get()['annotation_schema']['threat_levels']]
	lvl = annotation['labels'].get('threat_level')
	if lvl not in levels:
		return {'success': False, 'error': 'invalid_threat_level'}
	annotation['id'] = uuid.uuid4().hex
	annotation['timestamp'] = datetime.utcnow().isoformat()
	with open(ANNOTATIONS,'a') as f:
		f.write(json.dumps(annotation)+'\n')
	return {'success': True, 'id': annotation['id']}


def qa_report():
	total = 0; low_conf = 0; too_fast = 0
	try:
		with open(ANNOTATIONS,'r') as f:
			for line in f:
				total += 1
				ann = json.loads(line)
				if ann.get('confidence',1.0) < 0.6: low_conf += 1
				if ann.get('time_spent', 999) < 5: too_fast += 1
	except Exception:
		pass
	return {'total': total, 'low_confidence': low_conf, 'too_fast': too_fast}


def metrics():
	counts = {'critical':0,'high':0,'medium':0,'low':0,'benign':0}
	try:
		with open(ANNOTATIONS,'r') as f:
			for line in f:
				ann = json.loads(line)
				lvl = ann.get('labels',{}).get('threat_level')
				if lvl in counts: counts[lvl]+=1
	except Exception:
		pass
	return {'counts': counts}


def anonymize_sample(data: dict) -> dict:
	out = dict(data)
	if 'source_ip' in out:
		parts = str(out['source_ip']).split('.')
		if len(parts)==4:
			out['source_ip'] = f"{parts[0]}.{parts[1]}.XXX.XXX"
	if 'destination_ip' in out:
		parts = str(out['destination_ip']).split('.')
		if len(parts)==4:
			out['destination_ip'] = f"{parts[0]}.{parts[1]}.XXX.XXX"
	return out


def taxonomy_score(indicators: list) -> float:
	# Simple weighted score stub (indicators: names from guideline)
	weights = {
		'traffic_spike': 0.8*(1-0.1),
		'source_diversity': 0.7*(1-0.05),
		'sql_keywords': 0.9*(1-0.15)
	}
	return sum(weights.get(i, 0.1) for i in indicators)

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	sub = p.add_subparsers(dest='action', required=True)
	sub.add_parser('schema-init')
	sub.add_parser('schema-get')
	gb = sub.add_parser('get-batch'); gb.add_argument('--batch-size', type=int, default=10)
	sa = sub.add_parser('submit'); sa.add_argument('--annotation', required=True)
	sub.add_parser('qa-report')
	sub.add_parser('metrics')
	an = sub.add_parser('anonymize'); an.add_argument('--data', required=True)
	ts = sub.add_parser('taxonomy-score'); ts.add_argument('--indicators', required=True)
	args = p.parse_args()
	if args.action == 'schema-init':
		print(json.dumps({'success': schema_init()}))
	elif args.action == 'schema-get':
		print(json.dumps(schema_get()))
	elif args.action == 'get-batch':
		print(json.dumps(get_batch(args.batch_size)))
	elif args.action == 'submit':
		print(json.dumps(submit_annotation(json.loads(args.annotation))))
	elif args.action == 'qa-report':
		print(json.dumps(qa_report()))
	elif args.action == 'metrics':
		print(json.dumps(metrics()))
	elif args.action == 'anonymize':
		print(json.dumps(anonymize_sample(json.loads(args.data))))
	elif args.action == 'taxonomy-score':
		inds = json.loads(args.indicators); print(json.dumps({'score': taxonomy_score(inds)})) 