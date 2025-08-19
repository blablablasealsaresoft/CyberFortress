import React, { useState, useEffect } from 'react';
import { identityAPI, responseAPI } from '../services/api';

interface Identity {
  id?: number;
  name: string;
  email: string;
  phone?: string;
  ssn?: string;
  passport?: string;
  dob?: string;
  addresses?: string[];
  medical_ids?: string[];
  financial_accounts?: any[];
}

interface DarkWebAlert {
  data_type: string;
  marketplace: string;
  price: string;
  threat_level: string;
}

interface BreachInfo {
  service: string;
  breach_date: string;
  exposed_data: string[];
  severity: string;
}

export function IdentityProtectionDashboard() {
  const [activeTab, setActiveTab] = useState<'monitor' | 'breaches' | 'brokers' | 'darkweb' | 'report'>('monitor');
  const [identity, setIdentity] = useState<Identity>({
    name: '',
    email: '',
    phone: '',
    ssn: '',
    passport: '',
    dob: ''
  });
  const [identityId, setIdentityId] = useState<number | null>(null);
  const [darkWebAlerts, setDarkWebAlerts] = useState<DarkWebAlert[]>([]);
  const [breaches, setBreaches] = useState<BreachInfo[]>([]);
  const [brokerRemovalStatus, setBrokerRemovalStatus] = useState<any>(null);
  const [syntheticRisk, setSyntheticRisk] = useState<any>(null);
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState<any>(null);

  const styles = {
    container: {
      background: '#0d1117',
      border: '1px solid #30363d',
      borderRadius: 8,
      padding: 20,
      marginBottom: 20
    },
    tabs: {
      display: 'flex',
      gap: 10,
      marginBottom: 20,
      borderBottom: '1px solid #30363d',
      paddingBottom: 10
    },
    tab: {
      padding: '8px 16px',
      background: '#161b22',
      border: '1px solid #30363d',
      borderRadius: '6px 6px 0 0',
      color: '#e6edf3',
      cursor: 'pointer',
      transition: 'all 0.2s'
    },
    activeTab: {
      background: '#1f6feb',
      borderColor: '#1f6feb'
    },
    input: {
      width: '100%',
      padding: 8,
      marginBottom: 10,
      background: '#0d1117',
      border: '1px solid #30363d',
      color: '#e6edf3',
      borderRadius: 6
    },
    button: {
      padding: '8px 16px',
      background: '#238636',
      border: 'none',
      color: 'white',
      borderRadius: 6,
      cursor: 'pointer',
      marginRight: 10
    },
    dangerButton: {
      padding: '8px 16px',
      background: '#da3633',
      border: 'none',
      color: 'white',
      borderRadius: 6,
      cursor: 'pointer'
    },
    alert: {
      padding: 15,
      marginBottom: 10,
      borderRadius: 6,
      border: '1px solid'
    },
    critical: {
      background: 'rgba(218, 54, 51, 0.1)',
      borderColor: '#da3633',
      color: '#ff7b72'
    },
    high: {
      background: 'rgba(187, 128, 9, 0.1)',
      borderColor: '#bb8009',
      color: '#ffa657'
    },
    medium: {
      background: 'rgba(31, 111, 235, 0.1)',
      borderColor: '#1f6feb',
      color: '#79c0ff'
    },
    low: {
      background: 'rgba(35, 134, 54, 0.1)',
      borderColor: '#238636',
      color: '#7ee787'
    },
    grid: {
      display: 'grid',
      gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))',
      gap: 20
    },
    card: {
      background: '#161b22',
      border: '1px solid #30363d',
      borderRadius: 8,
      padding: 15
    },
    badge: {
      display: 'inline-block',
      padding: '4px 8px',
      borderRadius: 4,
      fontSize: 12,
      fontWeight: 'bold',
      marginLeft: 10
    }
  };

  const addIdentity = async () => {
    setLoading(true);
    try {
      const result = await identityAPI.add(identity);
      setIdentityId(result.identity_id);
      alert('Identity added for monitoring');
    } catch (error) {
      console.error('Error adding identity:', error);
    }
    setLoading(false);
  };

  const scanDarkWeb = async () => {
    if (!identityId) return alert('Add identity first');
    setLoading(true);
    try {
      const result = await identityAPI.scanDarkWeb(identityId);
      setDarkWebAlerts(result.darkweb_alerts || []);
      
      // Trigger automated response if critical threats found
      if (result.darkweb_alerts?.some((a: DarkWebAlert) => a.threat_level === 'CRITICAL')) {
        const response = await responseAPI.execute({
          type: 'identity',
          score: 85,
          email: identity.email,
          identity_id: identityId
        });
        alert('CRITICAL: Identity found on dark web! Automated response initiated.');
      }
    } catch (error) {
      console.error('Error scanning dark web:', error);
    }
    setLoading(false);
  };

  const checkBreaches = async () => {
    if (!identity.email) return alert('Email required');
    setLoading(true);
    try {
      const result = await identityAPI.checkBreaches(identity.email);
      setBreaches(result.breaches || []);
    } catch (error) {
      console.error('Error checking breaches:', error);
    }
    setLoading(false);
  };

  const removeBrokers = async (category: string = 'all') => {
    if (!identityId) return alert('Add identity first');
    setLoading(true);
    try {
      const result = await identityAPI.removeBrokers(identityId, category);
      setBrokerRemovalStatus(result);
      alert(`Data broker removal initiated: ${result.submitted?.length || 0} brokers`);
    } catch (error) {
      console.error('Error removing from brokers:', error);
    }
    setLoading(false);
  };

  const freezeCredit = async () => {
    if (!identityId) return alert('Add identity first');
    setLoading(true);
    try {
      const result = await identityAPI.freezeCredit(identityId);
      alert('Credit frozen with all bureaus');
      console.log('Credit freeze result:', result);
    } catch (error) {
      console.error('Error freezing credit:', error);
    }
    setLoading(false);
  };

  const checkSynthetic = async () => {
    setLoading(true);
    try {
      const result = await identityAPI.syntheticCheck(identity);
      setSyntheticRisk(result);
    } catch (error) {
      console.error('Error checking synthetic identity:', error);
    }
    setLoading(false);
  };

  const generateReport = async () => {
    if (!identityId) return alert('Add identity first');
    setLoading(true);
    try {
      const result = await identityAPI.getReport(identityId);
      setReport(result);
    } catch (error) {
      console.error('Error generating report:', error);
    }
    setLoading(false);
  };

  const getThreatLevelStyle = (level: string) => {
    switch (level) {
      case 'CRITICAL': return styles.critical;
      case 'HIGH': return styles.high;
      case 'MEDIUM': return styles.medium;
      case 'LOW': return styles.low;
      default: return {};
    }
  };

  return (
    <div>
      <h2 style={{ color: '#00ff88', marginBottom: 20 }}>🛡️ Identity Protection & Data Broker Removal</h2>
      
      <div style={styles.tabs}>
        <div 
          style={{...styles.tab, ...(activeTab === 'monitor' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('monitor')}
        >
          Monitor Identity
        </div>
        <div 
          style={{...styles.tab, ...(activeTab === 'breaches' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('breaches')}
        >
          Breach Detection
        </div>
        <div 
          style={{...styles.tab, ...(activeTab === 'brokers' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('brokers')}
        >
          Data Brokers
        </div>
        <div 
          style={{...styles.tab, ...(activeTab === 'darkweb' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('darkweb')}
        >
          Dark Web
        </div>
        <div 
          style={{...styles.tab, ...(activeTab === 'report' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('report')}
        >
          Report
        </div>
      </div>

      {activeTab === 'monitor' && (
        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Identity Monitoring Setup</h3>
          
          <div style={styles.grid}>
            <div>
              <input
                style={styles.input}
                placeholder="Full Name"
                value={identity.name}
                onChange={(e) => setIdentity({...identity, name: e.target.value})}
              />
              <input
                style={styles.input}
                placeholder="Email"
                value={identity.email}
                onChange={(e) => setIdentity({...identity, email: e.target.value})}
              />
              <input
                style={styles.input}
                placeholder="Phone"
                value={identity.phone}
                onChange={(e) => setIdentity({...identity, phone: e.target.value})}
              />
            </div>
            <div>
              <input
                style={styles.input}
                placeholder="SSN (will be hashed)"
                type="password"
                value={identity.ssn}
                onChange={(e) => setIdentity({...identity, ssn: e.target.value})}
              />
              <input
                style={styles.input}
                placeholder="Passport Number"
                value={identity.passport}
                onChange={(e) => setIdentity({...identity, passport: e.target.value})}
              />
              <input
                style={styles.input}
                placeholder="Date of Birth (YYYY-MM-DD)"
                value={identity.dob}
                onChange={(e) => setIdentity({...identity, dob: e.target.value})}
              />
            </div>
          </div>

          <div style={{ marginTop: 20 }}>
            <button style={styles.button} onClick={addIdentity} disabled={loading}>
              {loading ? 'Processing...' : 'Start Monitoring'}
            </button>
            <button style={styles.button} onClick={checkSynthetic} disabled={loading}>
              Check Synthetic Identity Risk
            </button>
            <button style={styles.dangerButton} onClick={freezeCredit} disabled={loading}>
              Emergency Credit Freeze
            </button>
          </div>

          {identityId && (
            <div style={{...styles.alert, ...styles.low, marginTop: 20}}>
              ✅ Identity monitoring active (ID: {identityId})
            </div>
          )}

          {syntheticRisk && (
            <div style={{...styles.alert, ...getThreatLevelStyle(syntheticRisk.risk_level), marginTop: 20}}>
              <strong>Synthetic Identity Risk Assessment:</strong>
              <div>Risk Score: {syntheticRisk.risk_score}/100</div>
              <div>Risk Level: {syntheticRisk.risk_level}</div>
              {syntheticRisk.risk_factors?.map((factor: string, i: number) => (
                <div key={i}>⚠️ {factor}</div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'breaches' && (
        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Data Breach Detection</h3>
          
          <div style={{ marginBottom: 20 }}>
            <button style={styles.button} onClick={checkBreaches} disabled={loading}>
              Check for Breaches
            </button>
          </div>

          {breaches.length > 0 && (
            <div>
              <h4 style={{ color: '#ff7b72', marginBottom: 10 }}>
                ⚠️ Found in {breaches.length} data breaches
              </h4>
              {breaches.map((breach, i) => (
                <div key={i} style={{...styles.alert, ...getThreatLevelStyle(breach.severity)}}>
                  <strong>{breach.service}</strong>
                  <span style={styles.badge}>{breach.severity}</span>
                  <div>Date: {breach.breach_date}</div>
                  <div>Exposed: {breach.exposed_data.join(', ')}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {activeTab === 'brokers' && (
        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Data Broker Removal</h3>
          
          <div style={{ marginBottom: 20 }}>
            <button style={styles.button} onClick={() => removeBrokers('all')} disabled={loading}>
              Remove from ALL Brokers (500+)
            </button>
            <button style={styles.button} onClick={() => removeBrokers('major_brokers')} disabled={loading}>
              Remove from Major Brokers
            </button>
            <button style={styles.button} onClick={() => removeBrokers('financial_brokers')} disabled={loading}>
              Remove from Financial Brokers
            </button>
          </div>

          {brokerRemovalStatus && (
            <div style={styles.card}>
              <h4 style={{ color: '#7ee787' }}>Removal Status</h4>
              <div>✅ Submitted: {brokerRemovalStatus.submitted?.length || 0} brokers</div>
              <div>⏳ Pending: {brokerRemovalStatus.pending?.length || 0} brokers</div>
              <div>❌ Failed: {brokerRemovalStatus.failed?.length || 0} brokers</div>
              
              {brokerRemovalStatus.submitted?.length > 0 && (
                <div style={{ marginTop: 10 }}>
                  <strong>Successfully submitted to:</strong>
                  <ul>
                    {brokerRemovalStatus.submitted.slice(0, 5).map((broker: string, i: number) => (
                      <li key={i}>{broker}</li>
                    ))}
                    {brokerRemovalStatus.submitted.length > 5 && (
                      <li>... and {brokerRemovalStatus.submitted.length - 5} more</li>
                    )}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {activeTab === 'darkweb' && (
        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Dark Web Monitoring</h3>
          
          <div style={{ marginBottom: 20 }}>
            <button style={styles.button} onClick={scanDarkWeb} disabled={loading}>
              Scan Dark Web
            </button>
          </div>

          {darkWebAlerts.length > 0 && (
            <div>
              <h4 style={{ color: '#ff7b72', marginBottom: 10 }}>
                🚨 Identity Found on Dark Web!
              </h4>
              {darkWebAlerts.map((alert, i) => (
                <div key={i} style={{...styles.alert, ...getThreatLevelStyle(alert.threat_level)}}>
                  <strong>{alert.data_type} Exposed</strong>
                  <span style={styles.badge}>{alert.threat_level}</span>
                  <div>Marketplace: {alert.marketplace}</div>
                  <div>Price: {alert.price}</div>
                </div>
              ))}
              <div style={{ marginTop: 20 }}>
                <button style={styles.dangerButton} onClick={freezeCredit}>
                  Emergency Credit Freeze
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'report' && (
        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Identity Protection Report</h3>
          
          <div style={{ marginBottom: 20 }}>
            <button style={styles.button} onClick={generateReport} disabled={loading}>
              Generate Report
            </button>
          </div>

          {report && (
            <div>
              <div style={styles.card}>
                <h4 style={{ color: '#7ee787' }}>Protection Status: {report.protection_status}</h4>
                <div>Risk Level: <span style={{...styles.badge, ...getThreatLevelStyle(report.risk_level)}}>{report.risk_level}</span></div>
                <div>Report Date: {report.report_date}</div>
              </div>

              <div style={{...styles.grid, marginTop: 20}}>
                <div style={styles.card}>
                  <h4>Summary</h4>
                  <div>Breaches Detected: {report.summary?.breaches_detected || 0}</div>
                  <div>Dark Web Exposures: {report.summary?.darkweb_exposures || 0}</div>
                  <div>Brokers Removed: {report.summary?.brokers_removed || 0}/{report.summary?.total_brokers || 0}</div>
                </div>

                <div style={styles.card}>
                  <h4>Recommendations</h4>
                  {report.recommendations?.map((rec: any, i: number) => (
                    <div key={i} style={{ marginBottom: 10 }}>
                      <span style={{...styles.badge, ...getThreatLevelStyle(rec.priority)}}>{rec.priority}</span>
                      <div>{rec.action}</div>
                      <small>{rec.reason}</small>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
