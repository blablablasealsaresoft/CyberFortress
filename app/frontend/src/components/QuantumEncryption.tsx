import React, { useState } from 'react';
import { quantumAPI } from '../services/api';

interface KeyPair {
  encryption: {
    public: string;
    private: string;
  };
  signature: {
    public: string;
    private: string;
  };
  algorithm: string;
}

interface ThreatAssessment {
  algorithm: string;
  quantum_vulnerable: boolean;
  estimated_break_time: string;
  risk_level: string;
  recommendation: string;
}

export function QuantumEncryptionPanel() {
  const [activeTab, setActiveTab] = useState<'encrypt' | 'keys' | 'assess' | 'vault' | 'qkd'>('encrypt');
  const [keyPair, setKeyPair] = useState<KeyPair | null>(null);
  const [plaintext, setPlaintext] = useState('');
  const [ciphertext, setCiphertext] = useState('');
  const [signature, setSignature] = useState('');
  const [securityLevel, setSecurityLevel] = useState<'low' | 'medium' | 'high'>('high');
  const [assessment, setAssessment] = useState<ThreatAssessment | null>(null);
  const [vaultInfo, setVaultInfo] = useState<any>(null);
  const [qkdResult, setQkdResult] = useState<any>(null);
  const [loading, setLoading] = useState(false);

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
      borderRadius: 6,
      fontFamily: 'monospace'
    },
    textarea: {
      width: '100%',
      padding: 8,
      marginBottom: 10,
      background: '#0d1117',
      border: '1px solid #30363d',
      color: '#e6edf3',
      borderRadius: 6,
      fontFamily: 'monospace',
      minHeight: 100,
      resize: 'vertical' as const
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
    select: {
      padding: 8,
      marginBottom: 10,
      background: '#0d1117',
      border: '1px solid #30363d',
      color: '#e6edf3',
      borderRadius: 6,
      marginRight: 10
    },
    codeBlock: {
      background: '#161b22',
      border: '1px solid #30363d',
      borderRadius: 6,
      padding: 10,
      fontFamily: 'monospace',
      fontSize: 12,
      wordBreak: 'break-all' as const,
      marginBottom: 10
    },
    grid: {
      display: 'grid',
      gridTemplateColumns: '1fr 1fr',
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
    },
    success: {
      background: 'rgba(35, 134, 54, 0.1)',
      borderColor: '#238636',
      color: '#7ee787'
    },
    danger: {
      background: 'rgba(218, 54, 51, 0.1)',
      borderColor: '#da3633',
      color: '#ff7b72'
    },
    warning: {
      background: 'rgba(187, 128, 9, 0.1)',
      borderColor: '#bb8009',
      color: '#ffa657'
    },
    info: {
      background: 'rgba(31, 111, 235, 0.1)',
      borderColor: '#1f6feb',
      color: '#79c0ff'
    }
  };

  const generateKeys = async () => {
    setLoading(true);
    try {
      const result = await quantumAPI.generateKeys(securityLevel);
      setKeyPair(result);
      alert(`Quantum-resistant keys generated (${result.algorithm})`);
    } catch (error) {
      console.error('Error generating keys:', error);
    }
    setLoading(false);
  };

  const encryptData = async () => {
    if (!keyPair || !plaintext) return alert('Generate keys and enter plaintext first');
    setLoading(true);
    try {
      const result = await quantumAPI.encrypt(
        btoa(plaintext), // Base64 encode
        keyPair.encryption.public,
        securityLevel
      );
      setCiphertext(JSON.stringify(result, null, 2));
    } catch (error) {
      console.error('Error encrypting:', error);
    }
    setLoading(false);
  };

  const decryptData = async () => {
    if (!keyPair || !ciphertext) return alert('Generate keys and enter ciphertext first');
    setLoading(true);
    try {
      const result = await quantumAPI.decrypt(
        ciphertext,
        keyPair.encryption.private
      );
      setPlaintext(atob(result.plaintext)); // Base64 decode
    } catch (error) {
      console.error('Error decrypting:', error);
    }
    setLoading(false);
  };

  const signData = async () => {
    if (!keyPair || !plaintext) return alert('Generate keys and enter data first');
    setLoading(true);
    try {
      const result = await quantumAPI.sign(
        plaintext,
        keyPair.signature.private
      );
      setSignature(result.signature);
    } catch (error) {
      console.error('Error signing:', error);
    }
    setLoading(false);
  };

  const verifySignature = async () => {
    if (!keyPair || !plaintext || !signature) return alert('Need data and signature');
    setLoading(true);
    try {
      const result = await quantumAPI.verify(
        plaintext,
        signature,
        keyPair.signature.public
      );
      alert(`Signature ${result.valid ? 'VALID ✅' : 'INVALID ❌'}`);
    } catch (error) {
      console.error('Error verifying:', error);
    }
    setLoading(false);
  };

  const assessAlgorithm = async (algorithm: string) => {
    setLoading(true);
    try {
      const result = await quantumAPI.assessThreat(algorithm);
      setAssessment(result);
    } catch (error) {
      console.error('Error assessing:', error);
    }
    setLoading(false);
  };

  const initVault = async () => {
    setLoading(true);
    try {
      const result = await quantumAPI.initVault();
      setVaultInfo(result);
      alert('Quantum-safe vault initialized');
    } catch (error) {
      console.error('Error initializing vault:', error);
    }
    setLoading(false);
  };

  const simulateQKD = async () => {
    setLoading(true);
    try {
      const result = await quantumAPI.simulateQKD();
      setQkdResult(result);
    } catch (error) {
      console.error('Error simulating QKD:', error);
    }
    setLoading(false);
  };

  const getRiskStyle = (level: string) => {
    switch (level) {
      case 'CRITICAL':
      case 'HIGH':
        return styles.danger;
      case 'MEDIUM':
        return styles.warning;
      case 'LOW':
      case 'NONE':
        return styles.success;
      default:
        return styles.info;
    }
  };

  return (
    <div>
      <h2 style={{ color: '#00ff88', marginBottom: 20 }}>🔐 Quantum-Resistant Encryption</h2>
      
      <div style={styles.tabs}>
        <div 
          style={{...styles.tab, ...(activeTab === 'encrypt' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('encrypt')}
        >
          Encrypt/Decrypt
        </div>
        <div 
          style={{...styles.tab, ...(activeTab === 'keys' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('keys')}
        >
          Key Management
        </div>
        <div 
          style={{...styles.tab, ...(activeTab === 'assess' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('assess')}
        >
          Threat Assessment
        </div>
        <div 
          style={{...styles.tab, ...(activeTab === 'vault' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('vault')}
        >
          Quantum Vault
        </div>
        <div 
          style={{...styles.tab, ...(activeTab === 'qkd' ? styles.activeTab : {})}}
          onClick={() => setActiveTab('qkd')}
        >
          QKD Simulator
        </div>
      </div>

      {activeTab === 'encrypt' && (
        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Hybrid Quantum-Safe Encryption</h3>
          
          <div style={{ marginBottom: 20 }}>
            <label>Security Level:</label>
            <select 
              style={styles.select} 
              value={securityLevel}
              onChange={(e) => setSecurityLevel(e.target.value as any)}
            >
              <option value="low">Low (Kyber512)</option>
              <option value="medium">Medium (Kyber768)</option>
              <option value="high">High (Kyber1024)</option>
            </select>
            
            <button style={styles.button} onClick={generateKeys} disabled={loading}>
              Generate Quantum-Safe Keys
            </button>
          </div>

          <div style={styles.grid}>
            <div>
              <h4>Plaintext</h4>
              <textarea
                style={styles.textarea}
                placeholder="Enter data to encrypt..."
                value={plaintext}
                onChange={(e) => setPlaintext(e.target.value)}
              />
              <button style={styles.button} onClick={encryptData} disabled={loading}>
                🔒 Encrypt
              </button>
              <button style={styles.button} onClick={signData} disabled={loading}>
                ✍️ Sign
              </button>
            </div>
            
            <div>
              <h4>Ciphertext</h4>
              <textarea
                style={styles.textarea}
                placeholder="Encrypted data will appear here..."
                value={ciphertext}
                onChange={(e) => setCiphertext(e.target.value)}
              />
              <button style={styles.button} onClick={decryptData} disabled={loading}>
                🔓 Decrypt
              </button>
            </div>
          </div>

          {signature && (
            <div style={{ marginTop: 20 }}>
              <h4>Digital Signature (Dilithium)</h4>
              <div style={styles.codeBlock}>{signature}</div>
              <button style={styles.button} onClick={verifySignature} disabled={loading}>
                ✅ Verify Signature
              </button>
            </div>
          )}
        </div>
      )}

      {activeTab === 'keys' && (
        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Quantum-Safe Key Management</h3>
          
          {!keyPair ? (
            <div>
              <p>No keys generated yet.</p>
              <button style={styles.button} onClick={generateKeys} disabled={loading}>
                Generate New Keypair
              </button>
            </div>
          ) : (
            <div>
              <div style={styles.card}>
                <h4>Algorithm: {keyPair.algorithm}</h4>
                <span style={{...styles.badge, ...styles.success}}>Quantum-Safe</span>
              </div>

              <div style={{...styles.grid, marginTop: 20}}>
                <div style={styles.card}>
                  <h4>Encryption Keys (Kyber)</h4>
                  <div style={{ marginBottom: 10 }}>
                    <strong>Public Key:</strong>
                    <div style={styles.codeBlock}>{keyPair.encryption.public.substring(0, 64)}...</div>
                  </div>
                  <div>
                    <strong>Private Key:</strong>
                    <div style={styles.codeBlock}>{'*'.repeat(64)}... (hidden)</div>
                  </div>
                </div>

                <div style={styles.card}>
                  <h4>Signature Keys (Dilithium)</h4>
                  <div style={{ marginBottom: 10 }}>
                    <strong>Public Key:</strong>
                    <div style={styles.codeBlock}>{keyPair.signature.public.substring(0, 64)}...</div>
                  </div>
                  <div>
                    <strong>Private Key:</strong>
                    <div style={styles.codeBlock}>{'*'.repeat(64)}... (hidden)</div>
                  </div>
                </div>
              </div>

              <div style={{ marginTop: 20 }}>
                <button style={styles.dangerButton} onClick={() => setKeyPair(null)}>
                  Delete Keys
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'assess' && (
        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Quantum Threat Assessment</h3>
          
          <div style={{ marginBottom: 20 }}>
            <h4>Test Common Algorithms</h4>
            <button style={styles.button} onClick={() => assessAlgorithm('RSA-2048')}>
              RSA-2048
            </button>
            <button style={styles.button} onClick={() => assessAlgorithm('ECC-256')}>
              ECC-256
            </button>
            <button style={styles.button} onClick={() => assessAlgorithm('AES-256')}>
              AES-256
            </button>
            <button style={styles.button} onClick={() => assessAlgorithm('SHA-256')}>
              SHA-256
            </button>
            <button style={styles.button} onClick={() => assessAlgorithm('Kyber1024')}>
              Kyber1024
            </button>
            <button style={styles.button} onClick={() => assessAlgorithm('Dilithium5')}>
              Dilithium5
            </button>
          </div>

          {assessment && (
            <div style={{...styles.card, ...getRiskStyle(assessment.risk_level)}}>
              <h4>Assessment: {assessment.algorithm}</h4>
              <div>
                <strong>Quantum Vulnerable:</strong> 
                <span style={{...styles.badge, ...(assessment.quantum_vulnerable ? styles.danger : styles.success)}}>
                  {assessment.quantum_vulnerable ? 'YES ⚠️' : 'NO ✅'}
                </span>
              </div>
              <div><strong>Estimated Break Time:</strong> {assessment.estimated_break_time}</div>
              <div>
                <strong>Risk Level:</strong>
                <span style={{...styles.badge, ...getRiskStyle(assessment.risk_level)}}>
                  {assessment.risk_level}
                </span>
              </div>
              <div style={{ marginTop: 10 }}>
                <strong>Recommendation:</strong>
                <div>{assessment.recommendation}</div>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'vault' && (
        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Quantum-Safe Vault</h3>
          
          <div style={{ marginBottom: 20 }}>
            <button style={styles.button} onClick={initVault} disabled={loading}>
              Initialize Quantum Vault
            </button>
          </div>

          {vaultInfo && (
            <div>
              <div style={styles.card}>
                <h4>Vault Initialized</h4>
                <div><strong>Algorithm:</strong> {vaultInfo.vault?.algorithm}</div>
                <div><strong>Created:</strong> {vaultInfo.vault?.created}</div>
                <div><strong>Salt:</strong> {vaultInfo.vault?.salt?.substring(0, 32)}...</div>
              </div>

              {vaultInfo.master_password && vaultInfo.master_password !== '***' && (
                <div style={{...styles.card, ...styles.warning, marginTop: 20}}>
                  <h4>⚠️ Master Password (Save This!)</h4>
                  <div style={styles.codeBlock}>{vaultInfo.master_password}</div>
                  <small>This password will not be shown again!</small>
                </div>
              )}

              <div style={{ marginTop: 20 }}>
                <h4>Vault Features</h4>
                <ul>
                  <li>✅ Post-quantum key derivation (SHA3-512)</li>
                  <li>✅ 1,000,000 iteration PBKDF2</li>
                  <li>✅ Kyber1024 key encapsulation</li>
                  <li>✅ Dilithium5 digital signatures</li>
                  <li>✅ AES-256-GCM for data encryption</li>
                  <li>✅ Quantum-safe secret storage</li>
                </ul>
              </div>
            </div>
          )}
        </div>
      )}

      {activeTab === 'qkd' && (
        <div style={styles.container}>
          <h3 style={{ color: '#58a6ff', marginBottom: 15 }}>Quantum Key Distribution (BB84 Protocol)</h3>
          
          <div style={{ marginBottom: 20 }}>
            <button style={styles.button} onClick={simulateQKD} disabled={loading}>
              Simulate QKD
            </button>
          </div>

          {qkdResult && (
            <div>
              <div style={styles.card}>
                <h4>QKD Simulation Result</h4>
                <div><strong>Protocol:</strong> {qkdResult.protocol}</div>
                <div><strong>Key Length:</strong> {qkdResult.key_length} bytes</div>
                <div><strong>Shared Key:</strong></div>
                <div style={styles.codeBlock}>{qkdResult.shared_key}</div>
              </div>

              <div style={{ marginTop: 20 }}>
                <h4>How BB84 Works</h4>
                <ol>
                  <li>Alice sends photons in random polarization bases</li>
                  <li>Bob measures in random bases</li>
                  <li>They compare bases (not values) over public channel</li>
                  <li>Keep only matching basis measurements</li>
                  <li>Check subset for eavesdropping</li>
                  <li>Use remaining bits as shared secret key</li>
                </ol>
                <div style={{...styles.card, ...styles.info, marginTop: 10}}>
                  <strong>Security:</strong> Any eavesdropping disturbs quantum states, 
                  revealing the intrusion with {'>'}99.9% probability
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
