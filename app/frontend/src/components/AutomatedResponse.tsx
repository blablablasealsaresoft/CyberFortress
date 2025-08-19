import React, { useState, useEffect } from 'react';
import { responseAPI, threatAPI } from '../services/api';

interface ThreatData {
  id?: string;
  type: string;
  score: number;
  ip_address?: string;
  email?: string;
  domain?: string;
  host?: string;
  pid?: number;
  file_path?: string;
}

interface ResponseResult {
  threat_id: string;
  threat_level: string;
  threat_score: number;
  actions_executed: string[];
  actions_failed: any[];
  evidence_collected: string[];
  case_id?: string;
  response_time: number;
  timestamp: string;
}

interface ResponseStats {
  responses_by_level: Record<string, number>;
  average_response_time: number;
  temporary_blocks: number;
  permanent_blocks: number;
  evidence_collected: number;
  timestamp: string;
}

export function AutomatedResponseDashboard() {
  const [threatData, setThreatData] = useState<ThreatData>({
    type: 'malware',
    score: 85,
    ip_address: '192.168.1.100'
  });
  const [responseResult, setResponseResult] = useState<ResponseResult | null>(null);
  const [assessment, setAssessment] = useState<any>(null);
  const [stats, setStats] = useState<ResponseStats | null>(null);
  const [threats, setThreats] = useState<any[]>([]);
  const [loading, setLoading] = useState(false);
  const [autoMode, setAutoMode] = useState(false);

  const styles = {
    container: {
      background: '#0d1117',
      border: '1px solid #30363d',
      borderRadius: 8,
      padding: 20,
      marginBottom: 20
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
    input: {
      width: '100%',
      padding: 8,
      marginBottom: 10,
      background: '#0d1117',
      border: '1px solid #30363d',
      color: '#e6edf3',
      borderRadius: 6
    },
    select: {
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
      cursor: 'pointer',
      marginRight: 10
    },
    warningButton: {
      padding: '8px 16px',
      background: '#bb8009',
      border: 'none',
      color: 'white',
      borderRadius: 6,
      cursor: 'pointer',
      marginRight: 10
    },
    badge: {
      display: 'inline-block',
      padding: '4px 8px',
      borderRadius: 4,
      fontSize: 12,
      fontWeight: 'bold',
      marginLeft: 10
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
    actionItem: {
      padding: '8px 12px',
      background: '#0d1117',
      border: '1px solid #30363d',
      borderRadius: 4,
      marginBottom: 5,
      display: 'flex',
      justifyContent: 'space-between',
      alignItems: 'center'
    },
    successIcon: {
      color: '#7ee787'
    },
    failIcon: {
      color: '#ff7b72'
    },
    toggle: {
      display: 'flex',
      alignItems: 'center',
      marginBottom: 20
    },
    switch: {
      position: 'relative' as const,
      width: 50,
      height: 24,
      background: '#30363d',
      borderRadius: 12,
      marginLeft: 10,
      cursor: 'pointer',
      transition: 'background 0.3s'
    },
    switchActive: {
      background: '#238636'
    },
    switchKnob: {
      position: 'absolute' as const,
      top: 2,
      left: 2,
      width: 20,
      height: 20,
      background: 'white',
      borderRadius: '50%',
      transition: 'transform 0.3s',
      transform: 'translateX(0)'
    },
    switchKnobActive: {
      transform: 'translateX(26px)'
    }
  };

  useEffect(() => {
    loadThreats();
    loadStats();
  }, []);

  useEffect(() => {
    if (autoMode) {
      const interval = setInterval(() => {
        checkAndRespondToThreats();
      }, 5000);
      return () => clearInterval(interval);
    }
  }, [autoMode]);

  const loadThreats = async () => {
    try {
      const result = await threatAPI.list();
      setThreats(result);
    } catch (error) {
      console.error('Error loading threats:', error);
    }
  };

  const loadStats = async () => {
    try {
      const result = await responseAPI.getStats();
      setStats(result);
    } catch (error) {
      console.error('Error loading stats:', error);
    }
  };

  const assessThreat = async () => {
    setLoading(true);
    try {
      const result = await responseAPI.assess(threatData);
      setAssessment(result);
    } catch (error) {
      console.error('Error assessing threat:', error);
    }
    setLoading(false);
  };

  const executeResponse = async () => {
    setLoading(true);
    try {
      const result = await responseAPI.execute(threatData);
      setResponseResult(result);
      loadStats(); // Refresh stats
      alert(`Response executed in ${result.response_time.toFixed(2)}s`);
    } catch (error) {
      console.error('Error executing response:', error);
    }
    setLoading(false);
  };

  const checkAndRespondToThreats = async () => {
    const recentThreats = threats.filter((t: any) => t.threat_score >= 60);
    for (const threat of recentThreats) {
      const threatData: ThreatData = {
        id: threat.id,
        type: 'network',
        score: threat.threat_score,
        ip_address: threat.ip_address
      };
      
      if (threat.threat_score >= 80) {
        // Auto-respond to critical threats
        await responseAPI.execute(threatData);
      }
    }
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

  const getThreatLevelFromScore = (score: number) => {
    if (score >= 80) return 'CRITICAL';
    if (score >= 60) return 'HIGH';
    if (score >= 40) return 'MEDIUM';
    if (score >= 20) return 'LOW';
    return 'INFO';
  };

  const getActionIcon = (action: string) => {
    const icons: Record<string, string> = {
      'block_ip': '🚫',
      'alert_admin': '📧',
      'collect_evidence': '📁',
      'initiate_osint': '🔍',
      'enable_quantum_encryption': '🔐',
      'create_case': '📋',
      'enhanced_monitoring': '👁️',
      'preserve_evidence': '💾',
      'identity_lock': '🔒',
      'credit_freeze': '❄️',
      'data_broker_removal': '🗑️',
      'legal_evidence': '⚖️',
      'isolate_host': '🔌',
      'kill_process': '💀',
      'quarantine_file': '🦠',
      'enable_vpn': '🛡️',
      'rotate_credentials': '🔑',
      'backup_critical': '💿',
      'notify_authorities': '🚨'
    };
    return icons[action] || '▶️';
  };

  return (
    <div>
      <h2 style={{ color: '#00ff88', marginBottom: 20 }}>⚡ Automated Response System</h2>
      
      <div style={styles.toggle}>
        <span>Auto-Response Mode:</span>
        <div 
          style={{...styles.switch, ...(autoMode ? styles.switchActive : {})}}
          onClick={() => setAutoMode(!autoMode)}
        >
          <div style={{...styles.switchKnob, ...(autoMode ? styles.switchKnobActive : {})}} />
        </div>
        <span style={{ marginLeft: 10, color: autoMode ? '#7ee787' : '#8b949e' }}>
          {autoMode ? 'ACTIVE' : 'INACTIVE'}
        </span>
      </div>

      <div style={styles.grid}>
        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Threat Configuration</h3>
          
          <select
            style={styles.select}
            value={threatData.type}
            onChange={(e) => setThreatData({...threatData, type: e.target.value})}
          >
            <option value="malware">Malware</option>
            <option value="identity">Identity Threat</option>
            <option value="crypto">Crypto/Blockchain</option>
            <option value="network">Network Attack</option>
            <option value="phishing">Phishing</option>
            <option value="ransomware">Ransomware</option>
          </select>

          <input
            style={styles.input}
            type="number"
            placeholder="Threat Score (0-100)"
            value={threatData.score}
            onChange={(e) => setThreatData({...threatData, score: parseInt(e.target.value) || 0})}
          />

          <input
            style={styles.input}
            placeholder="IP Address (optional)"
            value={threatData.ip_address || ''}
            onChange={(e) => setThreatData({...threatData, ip_address: e.target.value})}
          />

          <input
            style={styles.input}
            placeholder="Email (optional)"
            value={threatData.email || ''}
            onChange={(e) => setThreatData({...threatData, email: e.target.value})}
          />

          <input
            style={styles.input}
            placeholder="Process ID (optional)"
            type="number"
            value={threatData.pid || ''}
            onChange={(e) => setThreatData({...threatData, pid: parseInt(e.target.value) || undefined})}
          />

          <div style={{ marginTop: 20 }}>
            <button style={styles.button} onClick={assessThreat} disabled={loading}>
              Assess Threat
            </button>
            <button style={styles.dangerButton} onClick={executeResponse} disabled={loading}>
              Execute Response
            </button>
          </div>
        </div>

        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Response Statistics</h3>
          
          {stats && (
            <div>
              <div style={styles.card}>
                <h4>Response Metrics</h4>
                <div>Avg Response Time: {stats.average_response_time?.toFixed(2)}s</div>
                <div>Evidence Collected: {stats.evidence_collected}</div>
                <div>Temporary Blocks: {stats.temporary_blocks}</div>
                <div>Permanent Blocks: {stats.permanent_blocks}</div>
              </div>

              <div style={{...styles.card, marginTop: 10}}>
                <h4>Responses by Level</h4>
                {Object.entries(stats.responses_by_level || {}).map(([level, count]) => (
                  <div key={level} style={{ marginBottom: 5 }}>
                    <span style={{...styles.badge, ...getThreatLevelStyle(level)}}>{level}</span>
                    <span style={{ marginLeft: 10 }}>{count} responses</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {assessment && (
        <div style={{...styles.alert, ...getThreatLevelStyle(assessment.threat_level), marginTop: 20}}>
          <h4>Threat Assessment</h4>
          <div>
            <strong>Threat Level:</strong>
            <span style={styles.badge}>{assessment.threat_level}</span>
          </div>
          <div><strong>Threat Score:</strong> {assessment.threat_score}/100</div>
          <div style={{ marginTop: 10 }}>
            <strong>Recommended Actions:</strong>
            <ul style={{ marginTop: 5, marginLeft: 20 }}>
              {assessment.recommended_actions?.map((action: string, i: number) => (
                <li key={i}>
                  {getActionIcon(action)} {action.replace(/_/g, ' ').toUpperCase()}
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}

      {responseResult && (
        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Response Execution Result</h3>
          
          <div style={styles.grid}>
            <div style={styles.card}>
              <h4>Summary</h4>
              <div>Threat ID: {responseResult.threat_id}</div>
              <div>
                Level: 
                <span style={{...styles.badge, ...getThreatLevelStyle(responseResult.threat_level)}}>
                  {responseResult.threat_level}
                </span>
              </div>
              <div>Score: {responseResult.threat_score}/100</div>
              <div>Response Time: {responseResult.response_time.toFixed(3)}s</div>
              {responseResult.case_id && <div>Case ID: {responseResult.case_id}</div>}
            </div>

            <div style={styles.card}>
              <h4>Actions Executed ({responseResult.actions_executed.length})</h4>
              {responseResult.actions_executed.map((action, i) => (
                <div key={i} style={styles.actionItem}>
                  <span>
                    {getActionIcon(action)} {action.replace(/_/g, ' ')}
                  </span>
                  <span style={styles.successIcon}>✓</span>
                </div>
              ))}
              
              {responseResult.actions_failed.length > 0 && (
                <>
                  <h4 style={{ marginTop: 10 }}>Failed Actions</h4>
                  {responseResult.actions_failed.map((fail: any, i: number) => (
                    <div key={i} style={styles.actionItem}>
                      <span>{fail.action}</span>
                      <span style={styles.failIcon}>✗</span>
                    </div>
                  ))}
                </>
              )}
            </div>
          </div>

          {responseResult.evidence_collected.length > 0 && (
            <div style={{...styles.card, marginTop: 20}}>
              <h4>Evidence Collected</h4>
              <ul>
                {responseResult.evidence_collected.map((evidence, i) => (
                  <li key={i}>{evidence}</li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      <div style={styles.container}>
        <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Response Rules</h3>
        
        <div style={styles.grid}>
          <div style={{...styles.card, ...styles.critical}}>
            <h4>CRITICAL (80+)</h4>
            <ul style={{ fontSize: 14 }}>
              <li>🚫 Block IP automatically</li>
              <li>📧 Alert admin immediately</li>
              <li>📁 Collect forensic evidence</li>
              <li>🔍 Initiate OSINT investigation</li>
              <li>🔐 Enable quantum encryption</li>
              <li>📋 Create case file</li>
              <li>🔌 Isolate host</li>
              <li>⚖️ Collect legal evidence</li>
              <li>🚨 Notify authorities</li>
            </ul>
          </div>

          <div style={{...styles.card, ...styles.high}}>
            <h4>HIGH (60-79)</h4>
            <ul style={{ fontSize: 14 }}>
              <li>👁️ Enhanced monitoring</li>
              <li>📧 Admin notification</li>
              <li>💾 Evidence preservation</li>
              <li>🔒 Identity protection scan</li>
              <li>🗑️ Data broker check</li>
              <li>💿 Backup critical data</li>
            </ul>
          </div>

          <div style={{...styles.card, ...styles.medium}}>
            <h4>IDENTITY THREAT</h4>
            <ul style={{ fontSize: 14 }}>
              <li>🔒 Immediate identity lock</li>
              <li>❄️ Credit freeze initiation</li>
              <li>🗑️ Data broker removal</li>
              <li>🔍 OSINT on threat actor</li>
              <li>⚖️ Legal evidence collection</li>
            </ul>
          </div>

          <div style={{...styles.card, ...styles.low}}>
            <h4>CRYPTO THREAT</h4>
            <ul style={{ fontSize: 14 }}>
              <li>🔐 Enable quantum encryption</li>
              <li>🔑 Rotate credentials</li>
              <li>💿 Backup wallets</li>
              <li>📧 Alert admin</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
  );
}
