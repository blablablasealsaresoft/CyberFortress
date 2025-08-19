import React, { useState } from 'react'
import { BrowserRouter, Routes, Route, Link, useNavigate } from 'react-router-dom'
import { IdentityProtectionDashboard } from './components/IdentityProtection'
import { QuantumEncryptionPanel } from './components/QuantumEncryption'
import { AutomatedResponseDashboard } from './components/AutomatedResponse'
import { auth, callAction, wsClient } from './services/api'

function useAuth() {
  const [token, setToken] = React.useState<string | null>(() => auth.getToken())
  const save = (t: string) => { auth.setToken(t); setToken(t) }
  const clear = () => { auth.clearToken(); setToken(null) }
  return { token, save, clear }
}

function Layout({ children }: { children: React.ReactNode }) {
  const { token, clear } = useAuth()
  return (
    <div style={{ display: 'flex', minHeight: '100vh', background: '#0b0f13', color: '#e6edf3', fontFamily: 'Consolas, Menlo, Monaco, monospace' }}>
      <nav style={{ width: 260, padding: 16, borderRight: '1px solid #151b23', background: '#0d1117', overflowY: 'auto' }}>
        <h3 style={{ color: '#00ff88', marginBottom: 12 }}>CyberFortress Pro™</h3>
        <ul style={{ listStyle: 'none', padding: 0, lineHeight: '32px' }}>
          <li><Link to="/" style={{ color: '#58a6ff', textDecoration: 'none' }}>📊 Dashboard</Link></li>
          <li><Link to="/identity" style={{ color: '#58a6ff', textDecoration: 'none' }}>🛡️ Identity Protection</Link></li>
          <li><Link to="/quantum" style={{ color: '#58a6ff', textDecoration: 'none' }}>🔐 Quantum Encryption</Link></li>
          <li><Link to="/response" style={{ color: '#58a6ff', textDecoration: 'none' }}>⚡ Auto Response</Link></li>
          <li><Link to="/osint" style={{ color: '#58a6ff', textDecoration: 'none' }}>🔍 OSINT</Link></li>
          <li><Link to="/forensics" style={{ color: '#58a6ff', textDecoration: 'none' }}>🔬 Forensics</Link></li>
          <li><Link to="/blockchain" style={{ color: '#58a6ff', textDecoration: 'none' }}>💰 Blockchain</Link></li>
          <li><Link to="/ml" style={{ color: '#58a6ff', textDecoration: 'none' }}>🤖 ML Detection</Link></li>
          <li><Link to="/network" style={{ color: '#58a6ff', textDecoration: 'none' }}>🌐 Network</Link></li>
          <li><Link to="/playbooks" style={{ color: '#58a6ff', textDecoration: 'none' }}>📋 Playbooks</Link></li>
          <li><Link to="/actions" style={{ color: '#58a6ff', textDecoration: 'none' }}>⚙️ Actions</Link></li>
          <li><Link to="/auth" style={{ color: '#58a6ff', textDecoration: 'none' }}>🔑 Auth</Link></li>
        </ul>
        {token && (
          <button onClick={clear} style={{ marginTop: 16, background: '#161b22', border: '1px solid #30363d', color: '#e6edf3', padding: '6px 10px', borderRadius: 6 }}>Sign out</button>
        )}
      </nav>
      <main style={{ flex: 1, padding: 24 }}>{children}</main>
    </div>
  )
}

function AuthPage() {
  const nav = useNavigate()
  const { save } = useAuth()
  const [email, setEmail] = React.useState('admin@example.com')
  const [password, setPassword] = React.useState('ChangeMe!123')
  const [totp, setTotp] = React.useState('')
  async function login() {
    const r = await fetch('/api/auth/login', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ email, password, totp: totp || undefined }) })
    const j = await r.json()
    if (j.access_token) { save(j.access_token); nav('/') } else { alert(JSON.stringify(j)) }
  }
  return (
    <div>
      <h2 style={{ color: '#00ff88' }}>Auth</h2>
      <div style={{ marginTop: 12 }}>
        <input placeholder='email' value={email} onChange={e=>setEmail(e.target.value)} style={{ background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', padding:8, borderRadius:6, width:320 }} />
      </div>
      <div style={{ marginTop: 8 }}>
        <input type='password' placeholder='password' value={password} onChange={e=>setPassword(e.target.value)} style={{ background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', padding:8, borderRadius:6, width:320 }} />
      </div>
      <div style={{ marginTop: 8 }}>
        <input placeholder='totp (optional)' value={totp} onChange={e=>setTotp(e.target.value)} style={{ background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', padding:8, borderRadius:6, width:320 }} />
      </div>
      <button onClick={login} style={{ marginTop: 12, background:'#161b22', border:'1px solid #30363d', color:'#e6edf3', padding:'8px 12px', borderRadius:6 }}>Sign in</button>
    </div>
  )
}

function DashboardPage() {
  const { token } = useAuth()
  return (
    <div>
      <h2 style={{ color: '#00ff88' }}>Dashboard</h2>
      <div style={{ marginTop: 12 }}>
        <button disabled={!token} onClick={async()=>{ const r = await fetch('/api/monitoring/start',{method:'POST'}); alert('Monitoring started') }} style={{ background:'#161b22', border:'1px solid #30363d', color:'#e6edf3', padding:'8px 12px', borderRadius:6 }}>Start Monitoring</button>
        <button disabled={!token} onClick={async()=>{ const r = await fetch('/api/monitoring/stop',{method:'POST'}); alert('Monitoring stopped') }} style={{ marginLeft:8, background:'#161b22', border:'1px solid #30363d', color:'#e6edf3', padding:'8px 12px', borderRadius:6 }}>Stop Monitoring</button>
        <button onClick={async()=>{ const r = await fetch('/api/threats'); alert(JSON.stringify(await r.json(), null, 2)); }} style={{ marginLeft:8, background:'#161b22', border:'1px solid #30363d', color:'#e6edf3', padding:'8px 12px', borderRadius:6 }}>List Threats</button>
      </div>
    </div>
  )
}

function PlaybooksPage() {
  const { token } = useAuth()
  const [name, setName] = React.useState('quick')
  const [yaml, setYaml] = React.useState('name: quick\nsteps: []\n')
  return (
    <div>
      <h2 style={{ color: '#00ff88' }}>Playbooks</h2>
      <textarea value={yaml} onChange={e=>setYaml(e.target.value)} rows={10} style={{ width:'100%', background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', padding:8, borderRadius:6 }} />
      <div style={{ marginTop:8 }}>
        <input value={name} onChange={e=>setName(e.target.value)} style={{ background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', padding:8, borderRadius:6 }} />
        <button disabled={!token} onClick={async()=>{ await fetch('/api/soar/playbooks/load',{ method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ name, yaml }) }); alert('Loaded') }} style={{ marginLeft:8, background:'#161b22', border:'1px solid #30363d', color:'#e6edf3', padding:'8px 12px', borderRadius:6 }}>Load</button>
        <button onClick={async()=>{ const r = await fetch('/api/soar/playbooks'); alert(JSON.stringify(await r.json(), null, 2)); }} style={{ marginLeft:8, background:'#161b22', border:'1px solid #30363d', color:'#e6edf3', padding:'8px 12px', borderRadius:6 }}>List</button>
      </div>
    </div>
  )
}

function ActionsPage() {
  const { token } = useAuth()
  const [action, setAction] = React.useState('geo.block_countries')
  const [params, setParams] = React.useState('{"countries":["cn","ru"]}')
  async function run() {
    if (!token) return alert('Login first');
    const out = await callAction(token!, action, JSON.parse(params || '{}'))
    alert(JSON.stringify(out, null, 2))
  }
  return (
    <div>
      <h2 style={{ color: '#00ff88' }}>Actions</h2>
      <div>
        <input value={action} onChange={e=>setAction(e.target.value)} style={{ width:420, background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', padding:8, borderRadius:6 }} />
      </div>
      <div style={{ marginTop:8 }}>
        <textarea rows={6} value={params} onChange={e=>setParams(e.target.value)} style={{ width:'100%', background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', padding:8, borderRadius:6 }} />
      </div>
      <button onClick={run} style={{ marginTop:8, background:'#161b22', border:'1px solid #30363d', color:'#e6edf3', padding:'8px 12px', borderRadius:6 }}>Execute</button>
    </div>
  )
}

function OsintPage() {
  const { token } = useAuth()
  async function collect() {
    if (!token) return alert('Login first')
    const out = await callAction(token!, 'osint.collect', { target: 'https://example.com', case_id: 'case1' })
    alert(JSON.stringify(out, null, 2))
  }
  return (
    <div>
      <h2 style={{ color: '#00ff88' }}>OSINT</h2>
      <button onClick={collect} style={{ background:'#161b22', border:'1px solid #30363d', color:'#e6edf3', padding:'8px 12px', borderRadius:6 }}>Collect Example</button>
    </div>
  )
}

function ForensicsPage() {
  const { token } = useAuth()
  async function triage() {
    if (!token) return alert('Login first')
    const out = await callAction(token!, 'forensics.triage.run', { case_id: 'case2' })
    alert(JSON.stringify(out, null, 2))
  }
  return (
    <div>
      <h2 style={{ color: '#00ff88' }}>Forensics</h2>
      <button onClick={triage} style={{ background:'#161b22', border:'1px solid #30363d', color:'#e6edf3', padding:'8px 12px', borderRadius:6 }}>Run Triage</button>
    </div>
  )
}

// Additional page components for complete functionality
function BlockchainPage() {
  const { token } = useAuth()
  const [target, setTarget] = useState('')
  const [result, setResult] = useState<any>(null)
  
  return (
    <div>
      <h2 style={{ color: '#00ff88' }}>💰 Blockchain Security</h2>
      <div style={{ marginTop: 20 }}>
        <input 
          placeholder="Contract address to scan" 
          value={target} 
          onChange={e=>setTarget(e.target.value)}
          style={{ width: 400, background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', padding:8, borderRadius:6 }}
        />
        <button 
          onClick={async() => {
            if (!token) return alert('Login first')
            const res = await callAction(token, 'crypto.smart_contract.scan', { target })
            setResult(res)
          }}
          style={{ marginLeft:8, background:'#161b22', border:'1px solid #30363d', color:'#e6edf3', padding:'8px 12px', borderRadius:6 }}
        >
          Scan Contract
        </button>
      </div>
      {result && (
        <pre style={{ marginTop: 20, background: '#161b22', padding: 15, borderRadius: 8, overflow: 'auto' }}>
          {JSON.stringify(result, null, 2)}
        </pre>
      )}
    </div>
  )
}

function MLDashboard() {
  const { token } = useAuth()
  const [models, setModels] = useState<any[]>([])
  
  return (
    <div>
      <h2 style={{ color: '#00ff88' }}>🤖 Machine Learning Detection</h2>
      <div style={{ marginTop: 20 }}>
        <button 
          onClick={async() => {
            if (!token) return alert('Login first')
            const res = await callAction(token, 'ml.model.list', {})
            setModels(res.models || [])
          }}
          style={{ background:'#161b22', border:'1px solid #30363d', color:'#e6edf3', padding:'8px 12px', borderRadius:6 }}
        >
          List Models
        </button>
        <button 
          onClick={async() => {
            if (!token) return alert('Login first')
            await callAction(token, 'ml.firewall.adaptive_start', {})
            alert('Adaptive ML firewall started')
          }}
          style={{ marginLeft:8, background:'#238636', border:'none', color:'white', padding:'8px 12px', borderRadius:6 }}
        >
          Start Adaptive Firewall
        </button>
      </div>
      {models.length > 0 && (
        <div style={{ marginTop: 20 }}>
          <h3>Available Models</h3>
          <pre style={{ background: '#161b22', padding: 15, borderRadius: 8 }}>
            {JSON.stringify(models, null, 2)}
          </pre>
        </div>
      )}
    </div>
  )
}

function NetworkPage() {
  const { token } = useAuth()
  const [countries, setCountries] = useState('cn,ru,kp')
  
  return (
    <div>
      <h2 style={{ color: '#00ff88' }}>🌐 Network Security</h2>
      <div style={{ marginTop: 20 }}>
        <input 
          placeholder="Countries to block (comma-separated codes)" 
          value={countries} 
          onChange={e=>setCountries(e.target.value)}
          style={{ width: 400, background:'#0d1117', border:'1px solid #30363d', color:'#e6edf3', padding:8, borderRadius:6 }}
        />
        <button 
          onClick={async() => {
            if (!token) return alert('Login first')
            await callAction(token, 'geo.block_countries', { countries: countries.split(',').map(c => c.trim()) })
            alert('Countries blocked')
          }}
          style={{ marginLeft:8, background:'#da3633', border:'none', color:'white', padding:'8px 12px', borderRadius:6 }}
        >
          Block Countries
        </button>
      </div>
    </div>
  )
}

export default function AppRouter() {
  // Initialize WebSocket connection
  React.useEffect(() => {
    if (auth.isAuthenticated()) {
      wsClient.connect()
    }
    return () => wsClient.disconnect()
  }, [])

  return (
    <BrowserRouter>
      <Layout>
        <Routes>
          <Route path='/' element={<DashboardPage/>} />
          <Route path='/identity' element={<IdentityProtectionDashboard/>} />
          <Route path='/quantum' element={<QuantumEncryptionPanel/>} />
          <Route path='/response' element={<AutomatedResponseDashboard/>} />
          <Route path='/blockchain' element={<BlockchainPage/>} />
          <Route path='/ml' element={<MLDashboard/>} />
          <Route path='/network' element={<NetworkPage/>} />
          <Route path='/playbooks' element={<PlaybooksPage/>} />
          <Route path='/actions' element={<ActionsPage/>} />
          <Route path='/osint' element={<OsintPage/>} />
          <Route path='/forensics' element={<ForensicsPage/>} />
          <Route path='/auth' element={<AuthPage/>} />
        </Routes>
      </Layout>
    </BrowserRouter>
  )
} 