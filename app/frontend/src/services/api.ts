/**
 * CyberFortress API Service
 * Comprehensive API client for all backend endpoints
 */

const API_BASE = '/api';

// Auth token management
export const auth = {
  getToken: () => localStorage.getItem('cf_token'),
  setToken: (token: string) => localStorage.setItem('cf_token', token),
  clearToken: () => localStorage.removeItem('cf_token'),
  isAuthenticated: () => !!localStorage.getItem('cf_token')
};

// API request helper
async function apiRequest(endpoint: string, options: RequestInit = {}) {
  const token = auth.getToken();
  const headers: HeadersInit = {
    'Content-Type': 'application/json',
    ...(token && { 'Authorization': `Bearer ${token}` }),
    ...options.headers
  };

  const response = await fetch(`${API_BASE}${endpoint}`, {
    ...options,
    headers
  });

  if (!response.ok && response.status === 401) {
    auth.clearToken();
    window.location.href = '/auth';
  }

  return response.json();
}

// Call backend action
export async function callAction(action: string, params: any = {}, timeout: number = 30) {
  return apiRequest('/action', {
    method: 'POST',
    body: JSON.stringify({ action, params, timeout })
  });
}

// Authentication API
export const authAPI = {
  login: async (email: string, password: string, totp?: string) => {
    const response = await apiRequest('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password, totp })
    });
    if (response.access_token) {
      auth.setToken(response.access_token);
    }
    return response;
  },
  
  register: async (email: string, password: string) => {
    return apiRequest('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password })
    });
  },
  
  logout: () => {
    auth.clearToken();
  },
  
  validateToken: async () => {
    return apiRequest('/auth/me');
  }
};

// Threat Detection API
export const threatAPI = {
  list: async () => apiRequest('/threats'),
  
  get: async (id: string) => apiRequest(`/threats/${id}`),
  
  report: async (ip_address: string, threat_score: number) => {
    return apiRequest('/threats', {
      method: 'POST',
      body: JSON.stringify({ ip_address, threat_score })
    });
  },
  
  getScore: async () => apiRequest('/score')
};

// Identity Protection API
export const identityAPI = {
  add: async (identityData: any) => 
    callAction('identity.add', { identity_data: JSON.stringify(identityData) }),
  
  scanDarkWeb: async (identityId: number) => 
    callAction('identity.scan_darkweb', { identity_id: identityId }),
  
  removeBrokers: async (identityId: number, category: string = 'all') => 
    callAction('identity.remove_brokers', { identity_id: identityId, category }),
  
  checkBreaches: async (email: string) => 
    callAction('identity.check_breaches', { email }),
  
  freezeCredit: async (identityId: number) => 
    callAction('identity.freeze_credit', { identity_id: identityId }),
  
  monitorAccounts: async (accounts: any[]) => 
    callAction('identity.monitor_accounts', { accounts }),
  
  syntheticCheck: async (identityData: any) => 
    callAction('identity.synthetic_check', { identity_data: JSON.stringify(identityData) }),
  
  getReport: async (identityId: number) => 
    callAction('identity.report', { identity_id: identityId })
};

// Quantum Encryption API
export const quantumAPI = {
  generateKeys: async (securityLevel: string = 'high') => 
    callAction('quantum.keygen', { security_level: securityLevel }),
  
  encrypt: async (data: string, publicKey: string, securityLevel: string = 'high') => 
    callAction('quantum.encrypt', { data, public_key: publicKey, security_level: securityLevel }),
  
  decrypt: async (encryptedData: string, privateKey: string) => 
    callAction('quantum.decrypt', { encrypted_data: encryptedData, private_key: privateKey }),
  
  sign: async (data: string, privateKey: string) => 
    callAction('quantum.sign', { data, private_key: privateKey }),
  
  verify: async (data: string, signature: string, publicKey: string) => 
    callAction('quantum.verify', { data, signature, public_key: publicKey }),
  
  assessThreat: async (algorithm: string) => 
    callAction('quantum.assess_threat', { algorithm }),
  
  initVault: async (password?: string) => 
    callAction('quantum.vault_init', password ? { password } : {}),
  
  simulateQKD: async () => 
    callAction('quantum.qkd_simulate', {})
};

// Automated Response API
export const responseAPI = {
  execute: async (threatData: any) => 
    callAction('response.execute', { threat_data: threatData }),
  
  assess: async (threatData: any) => 
    callAction('response.assess', { threat_data: threatData }),
  
  getStats: async () => 
    callAction('response.stats', {})
};

// OSINT API
export const osintAPI = {
  startHarvest: async (target: string) => 
    callAction('osint.harvest.start', { target }),
  
  collect: async (target: string, caseId?: string) => 
    callAction('osint.collect', { target, case_id: caseId }),
  
  enrich: async (type: string, value: string, caseId?: string) => 
    callAction('osint.enrich', { type, value, case_id: caseId }),
  
  socialMedia: async (username: string) => 
    callAction('osint.social', { username }),
  
  generateGraph: async (caseId: string, format: string = 'json') => 
    callAction('osint.graph', { case_id: caseId, format })
};

// Forensics API
export const forensicsAPI = {
  collectArtifacts: async () => 
    callAction('forensics.collect_artifacts', {}),
  
  getProcessTree: async () => 
    callAction('forensics.get_process_tree', {}),
  
  captureMemory: async (caseId?: string) => 
    callAction('forensics.memory.capture', { case_id: caseId }),
  
  createDiskImage: async (target: string, caseId?: string) => 
    callAction('forensics.disk.image', { target, case_id: caseId }),
  
  exportEvents: async (caseId?: string) => 
    callAction('forensics.events.export', { case_id: caseId }),
  
  collectBrowser: async (caseId?: string) => 
    callAction('forensics.browser.collect', { case_id: caseId }),
  
  dumpRegistry: async (caseId?: string) => 
    callAction('forensics.registry.dump', { case_id: caseId }),
  
  yaraScan: async (rules: string, path: string) => 
    callAction('forensics.yara.scan', { rules, path }),
  
  runTriage: async (caseId?: string, yaraRules?: string) => 
    callAction('forensics.triage.run', { case_id: caseId, yara_rules: yaraRules }),
  
  startPcap: async (iface?: string, output?: string) => 
    callAction('forensics.pcap.start', { interface: iface, out: output }),
  
  stopPcap: async () => 
    callAction('forensics.pcap.stop', {})
};

// Blockchain Security API
export const blockchainAPI = {
  scanContract: async (target: string) => 
    callAction('crypto.smart_contract.scan', { target }),
  
  auditContract: async (target: string) => 
    callAction('crypto.contract.audit', { target }),
  
  detectRugpull: async (features: any) => 
    callAction('crypto.contract.rugpull', { features }),
  
  detectHoneypot: async (features: any) => 
    callAction('crypto.contract.honeypot', { features }),
  
  simulateTransaction: async (tx: any) => 
    callAction('crypto.tx.simulate', { tx }),
  
  protectMEV: async (tx: any) => 
    callAction('crypto.tx.mev_protect', { tx }),
  
  assessCrossChain: async (tx: any) => 
    callAction('crypto.cross_chain.assess', { tx }),
  
  monitorEvents: async (address: string, webhook?: string) => 
    callAction('crypto.event.monitor', { address, webhook })
};

// Machine Learning API
export const mlAPI = {
  ingestDataset: async (name: string, csv: string, target?: string) => 
    callAction('ml.dataset.ingest', { name, csv, target }),
  
  startTraining: async (dataset: string, algo: string = 'iforest', target?: string) => 
    callAction('ml.training.start', { dataset, algo, target }),
  
  getTrainingStatus: async () => 
    callAction('ml.training.status', {}),
  
  listModels: async () => 
    callAction('ml.model.list', {}),
  
  promoteModel: async (model: string) => 
    callAction('ml.model.promote', { model }),
  
  startInference: async (host: string = '127.0.0.1', port: number = 5055) => 
    callAction('ml.infer.start', { host, port }),
  
  stopInference: async () => 
    callAction('ml.infer.stop', {}),
  
  trainFirewall: async (minutes: number = 60) => 
    callAction('ml.firewall.train', { minutes }),
  
  detectAndApply: async (minutes: number = 10) => 
    callAction('ml.firewall.detect_apply', { minutes }),
  
  startAdaptive: async () => 
    callAction('ml.firewall.adaptive_start', {}),
  
  stopAdaptive: async () => 
    callAction('ml.firewall.adaptive_stop', {})
};

// Network Security API
export const networkAPI = {
  blockCountries: async (countries: string[]) => 
    callAction('geo.block_countries', { countries }),
  
  unblockCountries: async (countries: string[]) => 
    callAction('geo.unblock_countries', { countries }),
  
  blockIP: async (ip: string) => 
    callAction('endpoint.block_ip', { ip }),
  
  unblockIP: async (ip: string) => 
    callAction('endpoint.unblock_ip', { ip }),
  
  startDPI: async (iface?: string) => 
    callAction('dpi.start', { interface: iface }),
  
  stopDPI: async () => 
    callAction('dpi.stop', {}),
  
  enableVPN: async (config?: any) => 
    callAction('privacy.vpn.enable', { config }),
  
  disableVPN: async () => 
    callAction('privacy.vpn.disable', {})
};

// Monitoring API
export const monitoringAPI = {
  startThreatDetector: async () => 
    callAction('monitor.threat_detector.start', {}),
  
  stopThreatDetector: async () => 
    callAction('monitor.threat_detector.stop', {}),
  
  startIntegrity: async () => 
    callAction('monitor.integrity.start', {}),
  
  stopIntegrity: async () => 
    callAction('monitor.integrity.stop', {}),
  
  startNetworkAnalyzer: async () => 
    callAction('monitor.network_analyzer.start', {}),
  
  stopNetworkAnalyzer: async () => 
    callAction('monitor.network_analyzer.stop', {}),
  
  getStatus: async () => {
    return apiRequest('/monitoring/status');
  }
};

// Playbook/SOAR API
export const soarAPI = {
  loadPlaybook: async (name: string, yaml: string) => {
    return apiRequest('/soar/playbooks/load', {
      method: 'POST',
      body: JSON.stringify({ name, yaml })
    });
  },
  
  listPlaybooks: async () => apiRequest('/soar/playbooks'),
  
  executePlaybook: async (name: string) => {
    return apiRequest('/soar/execute', {
      method: 'POST',
      body: JSON.stringify({ name })
    });
  }
};

// WebSocket connection for real-time updates
export class WebSocketClient {
  private ws: WebSocket | null = null;
  private listeners: Map<string, Set<Function>> = new Map();
  
  connect() {
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host;
    this.ws = new WebSocket(`${protocol}//${host}/ws`);
    
    this.ws.onmessage = (event) => {
      const data = JSON.parse(event.data);
      this.emit(data.type, data);
    };
    
    this.ws.onerror = (error) => {
      console.error('WebSocket error:', error);
    };
    
    this.ws.onclose = () => {
      setTimeout(() => this.connect(), 5000);
    };
  }
  
  disconnect() {
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }
  
  on(event: string, callback: Function) {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);
  }
  
  off(event: string, callback: Function) {
    this.listeners.get(event)?.delete(callback);
  }
  
  emit(event: string, data: any) {
    this.listeners.get(event)?.forEach(callback => callback(data));
  }
  
  send(data: any) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(data));
    }
  }
}

export const wsClient = new WebSocketClient();
