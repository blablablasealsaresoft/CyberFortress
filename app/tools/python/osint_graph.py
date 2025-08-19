#!/usr/bin/env python3
import argparse, json, os, networkx as nx

BASE = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../data/osint'))

def load_json(path):
	try:
		return json.load(open(path,'r'))
	except Exception:
		return {}

if __name__ == '__main__':
	p = argparse.ArgumentParser()
	p.add_argument('--case-id', required=True)
	p.add_argument('--format', choices=['json','graphml'], default='json')
	args = p.parse_args()
	case_dir = os.path.join(BASE, args.case_id)
	arts = load_json(os.path.join(case_dir, 'artifacts.json'))
	enr = load_json(os.path.join(case_dir, 'enrichment.json'))
	G = nx.Graph()
	# Nodes
	for e in arts.get('emails', []): G.add_node(e, type='email')
	for p in arts.get('phones', []): G.add_node(p, type='phone')
	for d in arts.get('domains', []): G.add_node(d, type='domain')
	for l in arts.get('links', []): G.add_node(l, type='url')
	# Enrichment edges
	if isinstance(enr, dict) and enr.get('domain'):
		G.add_node(enr['domain'], type='domain')
		for rr, vals in enr.get('dns', {}).items():
			for v in vals:
				G.add_node(v, type=rr)
				G.add_edge(enr['domain'], v, relation=f'DNS_{rr}')
	# Email to domain
	for e in arts.get('emails', []):
		d = e.split('@')[-1]
		G.add_node(d, type='domain')
		G.add_edge(e, d, relation='email_domain')
	# Export
	out_path = os.path.join(case_dir, f'graph.{"graphml" if args.format=="graphml" else "json"}')
	if args.format=='graphml':
		nx.write_graphml(G, out_path)
	else:
		data = { 'nodes': [{ 'id': n, **G.nodes[n]} for n in G.nodes()], 'edges': [{ 'source': u, 'target': v, **G.edges[u,v]} for u,v in G.edges()] }
		open(out_path,'w').write(json.dumps(data))
	print(json.dumps({'success': True, 'graph': out_path, 'nodes': G.number_of_nodes(), 'edges': G.number_of_edges()})) 