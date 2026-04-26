import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  Shield, Activity, Server, Play, Square, LayoutDashboard, Terminal,
  AlertTriangle, CheckCircle, Zap, Database, Brain, Bug, Globe,
  Clock, ChevronDown, ChevronRight, Wifi, WifiOff, Check, X,
  History, Eye, Trash2, RefreshCw
} from 'lucide-react';
import axios from 'axios';
import { motion, AnimatePresence } from 'framer-motion';
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts';

const COLORS = ['#00ff41', '#00d0ff', '#ff003c', '#a855f7', '#f59e0b'];

const cleanANSI = (str) => str.replace(/\x1b\[[0-9;]*m/g, '');

const renderValue = (value) => {
  if (value === null || value === undefined) return '';
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') return value;
  if (Array.isArray(value)) return value.map(renderValue).join(' • ');
  if (typeof value === 'object') return JSON.stringify(value, null, 2);
  return String(value);
};

const getSeverityColor = (severity) => {
  switch (severity?.toUpperCase()) {
    case 'CRITICAL': return '#a855f7';
    case 'HIGH': return '#ff003c';
    case 'MEDIUM': return '#f59e0b';
    case 'LOW': return '#60a5fa';
    default: return '#6b7280';
  }
};

const API_LABELS = {
  nvd_api: { label: 'NVD API', icon: Database },
  exploit_db: { label: 'Exploit-DB', icon: Bug },
  gemini_ai: { label: 'Gemini AI', icon: Brain },
};

// ── Scan History stored in sessionStorage ────────────────────────────
const HISTORY_KEY = 'vulnscan_history';
const loadHistory = () => {
  try { return JSON.parse(sessionStorage.getItem(HISTORY_KEY) || '[]'); }
  catch { return []; }
};
const saveHistory = (history) => {
  try { sessionStorage.setItem(HISTORY_KEY, JSON.stringify(history.slice(0, 20))); }
  catch {}
};

function App() {
  const [activeTab, setActiveTab] = useState('scan'); // 'scan' | 'history'
  const [logs, setLogs] = useState([]);
  const [results, setResults] = useState(null);
  const [isScanning, setIsScanning] = useState(false);
  const [scanState, setScanState] = useState('idle');
  const [scanSteps, setScanSteps] = useState({});
  const [target, setTarget] = useState('127.0.0.1');
  const [ports, setPorts] = useState('common');
  const [aiEnabled, setAiEnabled] = useState(true);
  const [numCves, setNumCves] = useState(5);
  const [outputMode, setOutputMode] = useState('text');
  const [pcapPath, setPcapPath] = useState('');
  const [expandedCve, setExpandedCve] = useState(null);
  const [apiStatus, setApiStatus] = useState({ nvd_api: false, exploit_db: false, gemini_ai: false });
  const [apiStatusLoading, setApiStatusLoading] = useState(true);
  const [wsConnected, setWsConnected] = useState(false);
  const [scanHistory, setScanHistory] = useState(loadHistory);
  const [selectedHistoryItem, setSelectedHistoryItem] = useState(null);
  const [scanStartTime, setScanStartTime] = useState(null);
  const [elapsed, setElapsed] = useState(0);

  const PORT_PRESETS = [
    { label: 'Common', value: 'common' },
    { label: 'Web', value: '80,443,8080,8443,3000,8000' },
    { label: 'DB', value: '3306,5432,1433,27017,6379' },
    { label: 'SSH/FTP', value: '22,21,23,2222' },
    { label: 'Full', value: '1-65535' },
  ];

  const ws = useRef(null);
  const logsEndRef = useRef(null);
  const timerRef = useRef(null);

  // ── Fetch API status ──────────────────────────────────────────────
  const refreshApiStatus = useCallback(() => {
    setApiStatusLoading(true);
    axios.get('http://localhost:8000/status')
      .then(res => { setApiStatus(res.data); setApiStatusLoading(false); })
      .catch(() => { setApiStatus({ nvd_api: false, exploit_db: false, gemini_ai: false }); setApiStatusLoading(false); });
  }, []);

  const refreshScanStatus = useCallback(() => {
    axios.get('http://localhost:8000/scan-status')
      .then(res => { setScanState(res.data.status || 'idle'); })
      .catch(() => { setScanState('idle'); });
  }, []);

  useEffect(() => { refreshApiStatus(); refreshScanStatus(); }, [refreshApiStatus, refreshScanStatus]);

  useEffect(() => {
    if (!isScanning) {
      const interval = setInterval(refreshScanStatus, 5000);
      return () => clearInterval(interval);
    }
    return undefined;
  }, [isScanning, refreshScanStatus]);

  // ── WebSocket ─────────────────────────────────────────────────────
  const connectWs = useCallback(() => {
    if (ws.current && (ws.current.readyState === WebSocket.OPEN || ws.current.readyState === WebSocket.CONNECTING)) {
      return;
    }

    const socket = new WebSocket(`ws://${window.location.hostname}:8000/ws`);
    socket.onopen = () => {
      setWsConnected(true);
      ws.current = socket;
    };
    socket.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'log') {
          return; // Ignore backend log traffic for clean UI
        }
        if (data.type === 'step') {
          const payload = data.payload || {};
          setScanSteps(prev => ({ ...prev, [payload.step]: payload.status }));
          return;
        }
        if (data.type === 'results') {
          const payload = data.payload || data.data || {};
          const scanResult = payload.scan_results || payload.data || payload;
          const mergedResult = {
            ...scanResult,
            ai_analysis: (!Array.isArray(payload.ai_analysis) && payload.ai_analysis) ? payload.ai_analysis : scanResult.ai_analysis || payload.ai_analysis || [],
            ai_mitigation: payload.ai_mitigation || scanResult.ai_mitigation || { summary: '', steps: [] },
            ai_analysis_items: payload.ai_analysis_items || scanResult.ai_analysis_items || [],
          };
          setResults(mergedResult);
          setIsScanning(false);
          setScanState(payload.status === 'success' ? 'completed' : (payload.status === 'error' ? 'error' : (mergedResult?.stopped ? 'stopped' : 'completed')));
          clearInterval(timerRef.current);
          if (scanResult) {
            const entry = {
              id: Date.now(),
              target: scanResult.target || 'Unknown',
              time: new Date().toLocaleString(),
              openPorts: scanResult.hosts?.[0]?.open_ports?.length || scanResult.ports?.length || 0,
              cveCount: scanResult.hosts?.flatMap(h => h.open_ports?.flatMap(p => p.vulnerabilities || []) || []).length || scanResult.vulnerabilities?.length || 0,
              riskScore: scanResult.behavior_results?.host_profiles?.[0]?.risk_score ?? scanResult.behavior?.risk_score ?? null,
              data: scanResult,
            };
            setScanHistory(prev => {
              const updated = [entry, ...prev].slice(0, 20);
              saveHistory(updated);
              return updated;
            });
          }
        }
      } catch (err) {
        console.warn('WebSocket parse error:', err);
      }
    };
    socket.onerror = () => setWsConnected(false);
    socket.onclose = () => {
      setWsConnected(false);
      if (ws.current === socket) {
        ws.current = null;
      }
      setTimeout(connectWs, 3000);
    };
    ws.current = socket;
  }, []);

  useEffect(() => {
    connectWs();
    return () => { if (ws.current) ws.current.close(); };
  }, [connectWs]);

  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [logs]);

  // ── Elapsed timer ─────────────────────────────────────────────────
  useEffect(() => {
    if (isScanning) {
      setScanStartTime(Date.now());
      setElapsed(0);
      timerRef.current = setInterval(() => {
        setElapsed(prev => prev + 1);
      }, 1000);
    } else {
      clearInterval(timerRef.current);
    }
    return () => clearInterval(timerRef.current);
  }, [isScanning]);

  // ── Start scan ────────────────────────────────────────────────────
  const startScan = async () => {
    setIsScanning(true);
    setScanState('running');
    setScanSteps({});
    setLogs([]);
    setResults(null);
    setActiveTab('scan');
    try {
      const response = await axios.post('http://localhost:8000/start-scan', {
        target,
        ports,
        num_cves: Number(numCves),
        ai_enabled: aiEnabled,
        pcap_path: pcapPath || null,
        output_mode: outputMode
      });
      if (response.data.status !== 'running') {
        setLogs(prev => [...prev, { text: `❌ ${response.data.message || 'Failed to start scan.'}`, ts: Date.now() }]);
        setIsScanning(false);
        setScanState('idle');
        clearInterval(timerRef.current);
      }
    } catch (err) {
      setLogs(prev => [...prev, { text: `❌ Error: ${err.message}. Is the backend running on port 8000?`, ts: Date.now() }]);
      setIsScanning(false);
      setScanState('idle');
      clearInterval(timerRef.current);
    }
  };

  const stopScan = async () => {
    if (scanState === 'stopping') {
      return;
    }
    if (!isScanning && scanState !== 'running') {
      return;
    }

    setScanState('stopping');
    try {
      const response = await axios.post('http://localhost:8000/stop-scan');
      setLogs(prev => [...prev, { text: `⚠️ ${response.data.message || 'Stop request sent.'}`, ts: Date.now() }]);
      if (response.data.status === 'stopping') {
        setScanState('stopping');
      } else if (response.data.status === 'stopped') {
        setScanState('stopped');
      } else {
        setScanState('idle');
      }
    } catch (err) {
      setLogs(prev => [...prev, { text: `❌ Error: ${err.message}. Unable to stop scan.`, ts: Date.now() }]);
    }
  };

  const displayResults = activeTab === 'history' && selectedHistoryItem ? selectedHistoryItem.data : results;
  const scanHosts = displayResults?.hosts || [];
  const allCves = displayResults?.vulnerabilities || scanHosts.flatMap(h => h.open_ports?.flatMap(p => p.vulnerabilities || []) || []) || [];
  const openPortsData = (scanHosts[0]?.open_ports || displayResults?.ports || []).map(p => ({ name: `${p.port}/${p.service || p.protocol || 'tcp'}`, value: 1 })) || [];
  const displayCves = displayResults?.vulnerabilities || scanHosts.flatMap(h => h.open_ports?.flatMap(p => p.vulnerabilities || []) || []) || [];
  const displayPortsData = (scanHosts[0]?.open_ports || displayResults?.ports || []).map(p => ({ name: `${p.port}/${p.service || p.protocol || 'tcp'}`, value: 1 })) || [];  const TAB_ITEMS = [
    { id: 'scan', label: 'Scan', icon: Shield },
    { id: 'history', label: `History (${scanHistory.length})`, icon: History },
  ];
  return (
    <div className="ui-app-shell" style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>

      {/* ── Sidebar ── */}
      <div className="glass-card ui-sidebar-card" style={{ width: 290, margin: 16, padding: 20, display: 'flex', flexDirection: 'column', gap: 0, flexShrink: 0, overflowY: 'auto' }}>

        {/* Logo + WS indicator */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Shield style={{ color: '#00ff41', width: 26, height: 26 }} />
            <h1 style={{ margin: 0, fontSize: 17, fontWeight: 700, color: '#fff', letterSpacing: 3, fontFamily: 'inherit' }}>
              VULN<span style={{ color: '#00ff41' }}>SCAN</span>
            </h1>
          </div>
          <div className="ui-live-status" style={{ fontSize: 10, color: wsConnected ? '#00ff41' : '#ff6b6b' }}>
            <div className="ui-live-dot" />
            <span style={{ color: wsConnected ? '#00ff41' : '#ff6b6b' }}>{wsConnected ? 'LIVE' : 'OFF'}</span>
          </div>
        </div>

        {/* ── API Status Panel ── */}
        <div style={{ background: 'rgba(0,0,0,0.25)', borderRadius: 8, padding: '12px 14px', marginBottom: 20, border: '1px solid rgba(75,85,99,0.4)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
            <span style={{ fontSize: 10, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 2 }}>API Status</span>
            <button onClick={refreshApiStatus} style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#4b5563', padding: 2 }} title="Refresh status">
              <RefreshCw size={12} style={{ color: apiStatusLoading ? '#00ff41' : '#6b7280' }} className={apiStatusLoading ? 'animate-spin' : ''} />
            </button>
          </div>
          {Object.entries(API_LABELS).map(([key, { label, icon: Icon }]) => {
            const connected = apiStatus[key];
            return (
              <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 7 }}>
                {/* Checkbox */}
                <div style={{
                  width: 15, height: 15, borderRadius: 3, flexShrink: 0,
                  border: `1.5px solid ${connected ? '#00ff41' : '#4b5563'}`,
                  background: connected ? 'rgba(0,255,65,0.18)' : 'transparent',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  transition: 'all 0.3s'
                }}>
                  {connected && <Check size={9} style={{ color: '#00ff41' }} />}
                </div>
                <Icon size={12} style={{ color: connected ? '#00ff41' : '#4b5563', flexShrink: 0 }} />
                <span style={{ fontSize: 11, color: connected ? '#d1d5db' : '#4b5563', flex: 1 }}>{label}</span>
                <span style={{
                  fontSize: 9, fontWeight: 700, letterSpacing: 1, textTransform: 'uppercase',
                  color: connected ? '#00ff41' : '#6b7280',
                  background: connected ? 'rgba(0,255,65,0.12)' : 'rgba(75,85,99,0.2)',
                  padding: '2px 5px', borderRadius: 3,
                }}>{connected ? 'OK' : 'N/A'}</span>
              </div>
            );
          })}
        </div>

        {/* ── Scan config ── */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 16, flex: 1 }}>

          {/* Target */}
          <div>
            <label style={{ fontSize: 10, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 2 }}>Target</label>
            <input
              className="ui-input"
              value={target} onChange={e => setTarget(e.target.value)}
              style={{ width: '100%', padding: '8px 10px', fontSize: 13, marginTop: 6, boxSizing: 'border-box' }}
              placeholder="IP / hostname / CIDR"
            />
          </div>

          {/* Ports */}
          <div>
            <label style={{ fontSize: 10, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 2 }}>Ports</label>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 8, marginBottom: 6 }}>
              {PORT_PRESETS.map(preset => (
                <button key={preset.label} onClick={() => setPorts(preset.value)} className={`ui-ports-btn ${ports === preset.value ? 'active' : ''}`} style={{ padding: '4px 9px', fontSize: 11, cursor: 'pointer' }}>
                  {preset.label}
                </button>
              ))}
            </div>
            <input value={ports} onChange={e => setPorts(e.target.value)}
              className="ui-input"
              style={{ width: '100%', padding: '7px 10px', fontSize: 12, boxSizing: 'border-box' }}
              placeholder="Custom: 80,443,8080..." />
          </div>

          {/* Max CVEs */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between' }}>
              <label style={{ fontSize: 10, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 2 }}>Max CVEs / Port</label>
              <span style={{ fontSize: 11, color: '#00ff41', fontWeight: 700 }}>{numCves}</span>
            </div>
            <input type="range" min={1} max={20} value={numCves} onChange={e => setNumCves(e.target.value)}
              className="ui-range" style={{ width: '100%', marginTop: 8, cursor: 'pointer' }} />
          </div>

          {/* Output Format */}
          <div>
            <label style={{ fontSize: 10, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 2 }}>Output Format</label>
            <div style={{ display: 'flex', gap: 8, marginTop: 8 }}>
              {['text', 'json'].map(mode => (
                <button key={mode} onClick={() => setOutputMode(mode)} className={`ui-btn ui-output-toggle ${outputMode === mode ? 'active' : ''}`} style={{ flex: 1, padding: '6px 0', fontSize: 12, cursor: 'pointer', textTransform: 'uppercase', letterSpacing: 1 }}>
                  {mode}
                </button>
              ))}
            </div>
          </div>

          {/* PCAP Path */}
          <div>
            <label style={{ fontSize: 10, color: '#6b7280', textTransform: 'uppercase', letterSpacing: 2 }}>PCAP File Path</label>
            <input value={pcapPath} onChange={e => setPcapPath(e.target.value)}
              className="ui-input"
              style={{ width: '100%', padding: '8px 10px', fontSize: 12, marginTop: 6, boxSizing: 'border-box' }}
              placeholder="/path/to/capture.pcap" />
          </div>

          {/* AI Toggle */}
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <Brain size={13} style={{ color: aiEnabled ? '#00d0ff' : '#4b5563' }} />
              <span style={{ fontSize: 13, color: aiEnabled ? '#d1d5db' : '#6b7280' }}>AI Agent</span>
              {!apiStatus.gemini_ai && <span style={{ fontSize: 9, color: '#f59e0b', background: 'rgba(245,158,11,0.12)', padding: '1px 5px', borderRadius: 3, letterSpacing: 1 }}>NO KEY</span>}
            </div>
            <div className="ui-toggle-switch" onClick={() => setAiEnabled(!aiEnabled)}
              style={{ width: 44, height: 22, borderRadius: 11, position: 'relative', cursor: 'pointer', transition: 'background 0.3s', background: aiEnabled ? 'rgba(0,255,65,0.18)' : '#1b2430' }}>
              <div className="ui-toggle-thumb" style={{ left: aiEnabled ? 25 : 3 }} />
            </div>
          </div>

        </div>

        {/* Scan Buttons */}
        <div style={{ display: 'flex', gap: 10, marginTop: 20 }}>
          <button onClick={isScanning ? undefined : startScan} className="ui-btn ui-neon-action" style={{
            flex: 1,
            padding: '12px 0',
            borderRadius: 8,
            fontWeight: 700,
            fontSize: 14,
            cursor: isScanning ? 'not-allowed' : 'pointer',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 8,
            transition: 'all 0.3s'
          }}>
            {isScanning
              ? <><Square size={15} /> Scanning... ({elapsed}s)</>
              : <><Play size={15} /> Start Scan</>}
          </button>
          <button onClick={stopScan} disabled={!isScanning || scanState === 'stopping' || scanState !== 'running'} className="ui-btn ui-neon-action" style={{
            flex: 1,
            padding: '12px 0',
            borderRadius: 8,
            fontWeight: 700,
            fontSize: 14,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: 8,
            transition: 'all 0.3s',
            opacity: (!isScanning || scanState !== 'running') ? 0.55 : 1
          }}>
            <><AlertTriangle size={15} /> Stop Scan</>
          </button>
        </div>
      </div>

      {/* ── Main Panel ── */}
      <div style={{ flex: 1, padding: 16, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 14 }}>

        {/* Header bar */}
        <div className="glass-card ui-header-card" style={{ padding: '12px 20px', display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Terminal size={16} style={{ color: '#00ff41' }} />
            <span className="ui-terminal-title" style={{ fontSize: 13, color: '#00ff41' }}>
              API-Driven Vulnerability Intelligence Engine //&nbsp;
              <span style={{ color: isScanning || scanState === 'stopping' ? '#00ff41' : '#6b7280' }}>
                {scanState === 'running' ? `● SCANNING (${elapsed}s)`
                  : scanState === 'stopping' ? '● STOPPING'
                  : scanState === 'stopped' ? '○ STOPPED'
                  : scanState === 'completed' ? '○ COMPLETED'
                  : '○ IDLE'}
              </span>
            </span>
          </div>
          {/* Tab switcher */}
          <div style={{ display: 'flex', alignItems:'center', gap: 8 }}>
            <div className="ui-window-dots">
              <span></span><span></span><span></span>
            </div>
            <div style={{ display: 'flex', gap: 4 }}>
              {TAB_ITEMS.map(tab => (
                <button key={tab.id} onClick={() => setActiveTab(tab.id)} className={`ui-btn ui-tab-button ${activeTab === tab.id ? 'active' : ''}`} style={{ padding: '5px 12px', fontSize: 11, cursor: 'pointer', letterSpacing: 1, display: 'flex', alignItems: 'center', gap: 5 }}>
                  <tab.icon size={11} /> {tab.label}
                </button>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 6, marginLeft: 8 }}>
              <div className="ui-window-dot-red" />
              <div className="ui-window-dot-yellow" />
              <div className="ui-window-dot-green" />
            </div>
          </div>
        </div>

        {/* ══════════════ SCAN TAB ══════════════ */}
        {activeTab === 'scan' && (
          <>
            {/* Live log terminal */}
            <AnimatePresence>
              {isScanning && (
                <motion.div className="glass-card" initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: 'auto' }} exit={{ opacity: 0, height: 0 }} style={{ padding: 18, flexShrink: 0 }}>
                  <h3 style={{ color: '#00ff41', margin: '0 0 10px', display: 'flex', alignItems: 'center', gap: 8, fontSize: 13 }}>
                    <Activity size={14} className="animate-spin" /> Live Scan Stream
                    <span style={{ marginLeft: 'auto', fontSize: 11, color: '#6b7280', fontWeight: 400 }}>{elapsed}s elapsed</span>
                  </h3>
                  {Object.keys(scanSteps).length > 0 && (
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 12, fontSize: 12, color: '#d1d5db' }}>
                      {Object.entries(scanSteps).map(([step, status]) => (
                        <div key={step} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ color: status === 'done' ? '#00ff41' : '#f59e0b' }}>
                            {status === 'done' ? '✔' : '●'}
                          </span>
                          <span>{step} — {status}</span>
                        </div>
                      ))}
                    </div>
                  )}
                  <div style={{ background: '#081014', borderRadius: 10, padding: 14, height: 180, overflowY: 'auto', fontSize: 12 }}>
                    {logs.length === 0 && <p style={{ color: '#4b5563', margin: 0 }}>Connecting to backend... (this may take a few seconds)</p>}
                    {logs.map((log, i) => (
                      <div key={i} style={{ color: log.text.startsWith('❌') ? '#ef4444' : log.text.startsWith('✅') ? '#00ff41' : '#a3e635', marginBottom: 3 }}>
                        &gt; {log.text}
                      </div>
                    ))}
                    <div ref={logsEndRef} />
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            {/* Results */}
            <AnimatePresence>
              {results && !isScanning && (
                <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                  <ResultsDashboard results={results} allCves={allCves} openPortsData={openPortsData} expandedCve={expandedCve} setExpandedCve={setExpandedCve} />
                </motion.div>
              )}
            </AnimatePresence>

            {/* Empty state */}
            {!isScanning && !results && (
              <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 16, color: '#334155', minHeight: 300 }}>
                <Shield size={72} />
                <p style={{ fontSize: 14, letterSpacing: 2, margin: 0 }}>CONFIGURE A TARGET AND START A SCAN</p>
                <p style={{ fontSize: 11, color: '#1e3a5f', margin: 0 }}>Make sure the backend is running on localhost:8000</p>
              </div>
            )}
          </>
        )}

        {/* ══════════════ HISTORY TAB ══════════════ */}
        {activeTab === 'history' && (
          <HistoryTab
            scanHistory={scanHistory}
            setScanHistory={setScanHistory}
            selectedHistoryItem={selectedHistoryItem}
            setSelectedHistoryItem={setSelectedHistoryItem}
            expandedCve={expandedCve}
            setExpandedCve={setExpandedCve}
          />
        )}
      </div>
    </div>
  );
}

// ── Results Dashboard component ───────────────────────────────────────
function ResultsDashboard({ results, allCves, openPortsData, expandedCve, setExpandedCve }) {
  if (!results) return null;

  const behaviorData = results.behavior || results.behavior_results;
  const behaviorProfiles = behaviorData?.host_profiles || (behaviorData ? [behaviorData] : []);
  const aiData = results.ai_summary || (results.ai_analysis && !Array.isArray(results.ai_analysis) ? results.ai_analysis : {});
  const aiChainMeta = results.ai_chain || aiData?.vulnerability_intel || {};

  const openPorts = results.hosts?.[0]?.open_ports || results.ports || [];
  const exploitRows = allCves.flatMap((cve, idx) => (cve.exploits || []).map((ex, ei) => ({
    id: `${cve.cve_id}-${ei}-${idx}`,
    cve_id: cve.cve_id,
    title: ex.description || ex.title || `Exploit ${ex.edb_id}`,
    link: ex.exploit_url || ex.url || '#',
    severity: cve.severity || 'UNKNOWN',
  })));

  const aiAnalysisItems = Array.isArray(results.ai_analysis_items)
    ? results.ai_analysis_items
    : (Array.isArray(results.ai_analysis) ? results.ai_analysis : []);

  return (
    <>
      {/* Row 1 */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2fr', gap: 14 }}>
        {/* Target Info */}
        <div className="glass-card" style={{ padding: 22, borderLeft: '3px solid #00ff41' }}>
          <h3 style={{ margin: '0 0 14px', color: '#fff', display: 'flex', alignItems: 'center', gap: 8, fontSize: 14, fontFamily: 'inherit' }}><Server size={14} /> Target Info</h3>
          <p style={{ margin: '0 0 6px', fontSize: 13, fontFamily: 'inherit' }}>IP: <strong style={{ color: '#fff' }}>{results.hosts?.[0]?.ip}</strong></p>
          <p style={{ margin: '0 0 6px', fontSize: 13, fontFamily: 'inherit' }}>Scan Time: <strong style={{ color: '#fff', fontSize: 11 }}>{results.scan_time}</strong></p>
          <p style={{ margin: '0 0 16px', fontSize: 13, fontFamily: 'inherit' }}>Open Ports: <strong style={{ color: '#00ff41', fontSize: 18 }}>{openPorts.length}</strong></p>
          {results.analysis && (
            <p style={{ margin: '0 0 8px', fontSize: 12, lineHeight: 1.5, color: '#cbd5e1' }}><strong>AI Summary:</strong> {renderValue(results.analysis)}</p>
          )}
          {results.mitigation && (
            <p style={{ margin: '0 0 16px', fontSize: 12, lineHeight: 1.5, color: '#a5f3fc' }}><strong>Recommended Mitigation:</strong> {renderValue(results.mitigation)}</p>
          )}
          <div style={{ minHeight: 160, height: 160 }}>
            {openPortsData.length > 0 ? (
              <ResponsiveContainer width="100%" height={160}>
                <PieChart>
                  <Pie data={openPortsData} cx="50%" cy="50%" innerRadius={32} outerRadius={50} dataKey="value" label={({ name }) => name}>
                    {openPortsData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                  </Pie>
                  <Tooltip contentStyle={{ background: '#0d1117', border: '1px solid rgba(0,255,65,0.16)', fontSize: 12, color: '#d1d5db' }} />
                </PieChart>
              </ResponsiveContainer>
            ) : (
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#6b7280', fontSize: 12 }}>
                No port chart data available.
              </div>
            )}
          </div>
        </div>

        {/* Behavior Analysis */}
        <div className="glass-card" style={{ padding: 22 }}>
          <h3 style={{ margin: '0 0 14px', color: '#fff', display: 'flex', alignItems: 'center', gap: 8, fontSize: 14 }}><Activity size={14} /> Behavior Analysis</h3>
          {behaviorProfiles.map((prof, i) => (
            <div key={i} style={{ marginBottom: 16 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                <span style={{ fontSize: 13, color: '#d1d5db' }}>Risk Score</span>
                <span style={{ color: prof.risk_score > 70 ? '#ff4d8d' : '#f5c32b', fontWeight: 700 }}>{prof.risk_score}/100 — {prof.risk_level}</span>
              </div>
              <div style={{ background: '#081014', borderRadius: 99, height: 8, marginBottom: 18, overflow: 'hidden', border: '1px solid rgba(0,255,65,0.18)' }}>
                <motion.div initial={{ width: 0 }} animate={{ width: `${prof.risk_score}%` }} transition={{ duration: 1.2, ease: 'easeOut' }}
                  style={{ height: '100%', borderRadius: 99, background: prof.risk_score > 70 ? 'linear-gradient(90deg, #ff4d8d, #ff003c)' : 'linear-gradient(90deg, #00ff41, #00d0ff)' }} />
              </div>
              {prof.findings?.length > 0 && (
                <div>
                  <p style={{ fontSize: 10, color: '#6b7280', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 1 }}>Findings</p>
                  {prof.findings.map((f, j) => (
                    <div key={j} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', marginBottom: 5, fontSize: 13, color: '#f5c32b' }}>
                      <AlertTriangle size={13} style={{ color: '#f5c32b', flexShrink: 0, marginTop: 1 }} />
                      <span>{typeof f === 'string' ? f : f.title || f.reason || JSON.stringify(f)}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* Structured result tables */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
        <div className="glass-card" style={{ padding: 22 }}>
          <h3 style={{ margin: '0 0 14px', color: '#fff', display: 'flex', alignItems: 'center', gap: 8, fontSize: 14 }}><Server size={14} /> Open Ports</h3>
          <div style={{ overflowX: 'auto' }}>
            <table className="ui-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
              <thead>
                <tr>
                  {['Port', 'Service', 'Status'].map(h => (
                    <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {openPorts.map((port, i) => (
                  <tr key={i} style={{ borderBottom: '1px solid rgba(51,65,85,0.5)' }}>
                    <td style={{ padding: '10px 14px' }}>{port.port}</td>
                    <td style={{ padding: '10px 14px' }}>{port.service || port.protocol || 'tcp'}</td>
                    <td style={{ padding: '10px 14px', color: '#00ff41' }}>{port.status || 'open'}</td>
                  </tr>
                ))}
                {openPorts.length === 0 && (
                  <tr><td colSpan={3} style={{ padding: 18, textAlign: 'center', color: '#4b5563' }}>No open ports detected.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        <div className="glass-card" style={{ padding: 22 }}>
          <h3 style={{ margin: '0 0 14px', color: '#fff', display: 'flex', alignItems: 'center', gap: 8, fontSize: 14 }}><Bug size={14} /> Exploits</h3>
          <div style={{ overflowX: 'auto' }}>
            <table className="ui-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, fontFamily: 'inherit' }}>
              <thead>
                <tr>
                  {['CVE', 'Title', 'Severity', 'Link'].map(h => (
                    <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 600 }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {exploitRows.map(row => (
                  <tr key={row.id} style={{ borderBottom: '1px solid rgba(51,65,85,0.5)' }}>
                    <td style={{ padding: '10px 14px' }}>{row.cve_id}</td>
                    <td style={{ padding: '10px 14px' }}>{row.title}</td>
                    <td style={{ padding: '10px 14px' }}><span className={`ui-severity-label ui-severity-label-${row.severity?.toLowerCase()}`}>{row.severity}</span></td>
                    <td style={{ padding: '10px 14px' }}><a href={row.link} target="_blank" rel="noreferrer" style={{ color: '#38bdf8' }}>Open</a></td>
                  </tr>
                ))}
                {exploitRows.length === 0 && (
                  <tr><td colSpan={4} style={{ padding: 18, textAlign: 'center', color: '#4b5563' }}>No exploit data found.</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <div className="glass-card ui-ai-card" style={{ padding: 22 }}>
        <h3 style={{ margin: '0 0 14px', color: '#fff', display: 'flex', alignItems: 'center', gap: 8, fontSize: 14 }}><Brain size={14} /> AI Analysis</h3>
        <div style={{ overflowX: 'auto' }}>
          <table className="ui-table" style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13, fontFamily: 'inherit' }}>
            <thead>
              <tr style={{ background: 'rgba(30,41,59,0.8)', color: '#6b7280', textTransform: 'uppercase', fontSize: 10, letterSpacing: 1 }}>
                {['Severity', 'Finding', 'Reason', 'Recommendation'].map(h => (
                  <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 600 }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {aiAnalysisItems.map((item, idx) => (
                <tr key={item.id || idx} style={{ borderBottom: '1px solid rgba(51,65,85,0.5)' }}>
                  <td style={{ padding: '10px 14px', color: getSeverityColor(item.severity) }}>{item.severity}</td>
                  <td style={{ padding: '10px 14px' }}>{item.finding}</td>
                  <td style={{ padding: '10px 14px' }}>{item.reason}</td>
                  <td style={{ padding: '10px 14px' }}>{item.recommendation}</td>
                </tr>
              ))}
              {aiAnalysisItems.length === 0 && (
                <tr><td colSpan={4} style={{ padding: 18, textAlign: 'center', color: '#4b5563' }}>No AI findings available.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="glass-card ui-ai-card" style={{ padding: 22 }}>
        <h3 style={{ margin: '0 0 14px', color: '#fff', display: 'flex', alignItems: 'center', gap: 8, fontSize: 14 }}><Shield size={14} /> AI Mitigation</h3>
        <p style={{ margin: '0 0 12px', fontSize: 13, color: '#cbd5e1', fontFamily: 'inherit' }}>{renderValue(results.ai_mitigation?.summary) || 'No AI mitigation summary available.'}</p>
        {Array.isArray(results.ai_mitigation?.steps) && results.ai_mitigation.steps.length > 0 ? (
          <ul className="ui-terminal-list" style={{ margin: 0, fontSize: 13 }}>
            {results.ai_mitigation.steps.map((step, idx) => (
              <li key={idx} style={{ marginBottom: 6 }}>{renderValue(step)}</li>
            ))}
          </ul>
        ) : (
          <p style={{ margin: 0, fontSize: 12, color: '#6b7280' }}>No mitigation steps available.</p>
        )}
      </div>

      {/* CVE Table */}
      <CveTable allCves={allCves} expandedCve={expandedCve} setExpandedCve={setExpandedCve} />
    </>
  );
}

// ── CVE Table ─────────────────────────────────────────────────────────
function CveTable({ allCves, expandedCve, setExpandedCve }) {
  return (
    <div className="glass-card" style={{ padding: 22 }}>
      <h3 style={{ margin: '0 0 14px', color: '#fff', display: 'flex', alignItems: 'center', gap: 8, fontSize: 14 }}>
        <LayoutDashboard size={14} /> Detected Vulnerabilities ({allCves.length})
      </h3>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
          <thead>
            <tr style={{ background: 'rgba(30,41,59,0.8)', color: '#6b7280', textTransform: 'uppercase', fontSize: 10, letterSpacing: 1 }}>
              {['S.No', 'Port', 'CVE ID', 'Severity', 'Score', 'Exploit', 'CWE Type'].map(h => (
                <th key={h} style={{ padding: '10px 14px', textAlign: 'left', fontWeight: 600 }}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody>
            {allCves.map((cve, idx) => {
              const rowKey = `${cve.cve_id}-${cve.port ?? 'unknown'}-${idx}`;
              return (
                <React.Fragment key={rowKey}>
                  <tr onClick={() => setExpandedCve(expandedCve === rowKey ? null : rowKey)}
                    className="ui-table-row"
                    style={{ borderBottom: '1px solid rgba(51,65,85,0.5)', cursor: 'pointer', transition: 'background 0.2s' }}
                    onMouseEnter={e => e.currentTarget.style.background = 'rgba(0,255,65,0.08)'}
                    onMouseLeave={e => e.currentTarget.style.background = 'transparent'}>
                    <td style={{ padding: '10px 14px', color: '#fff', fontWeight: 700 }}>{idx + 1}</td>
                    <td style={{ padding: '10px 14px', color: '#d1d5db' }}>{cve.port ?? '-'}</td>
                    <td style={{ padding: '10px 14px', color: '#fff', fontWeight: 700 }}>{cve.cve_id}</td>
                    <td style={{ padding: '10px 14px' }}><span className={`ui-severity-label ui-severity-label-${cve.severity?.toLowerCase()}`} style={{ fontWeight: 700 }}>{cve.severity}</span></td>
                    <td style={{ padding: '10px 14px' }}>{cve.cvss_score}</td>
                    <td style={{ padding: '10px 14px' }}>
                      {cve.exploit_available ? (
                        <span style={{ color: '#ff003c', fontWeight: 700 }}>✔ Yes</span>
                      ) : (
                        <span style={{ color: '#4b5563' }}>✘ No</span>
                      )}
                    </td>
                    <td style={{ padding: '10px 14px', maxWidth: 220, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{cve.cwe}</td>
                  </tr>
                  <AnimatePresence>
                    {expandedCve === rowKey && (
                      <motion.tr initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}>
                        <td colSpan={7} className="ui-expand-panel" style={{ padding: 18, borderBottom: '1px solid rgba(51,65,85,0.5)' }}>
                          <p style={{ margin: '0 0 8px', fontSize: 13 }}><strong style={{ color: '#d1d5db' }}>Description:</strong> {renderValue(cve.description)}</p>
                          <p style={{ margin: '0 0 8px', fontSize: 13, color: '#00ff41' }}><strong>Mitigation:</strong> {renderValue(cve.mitigation)}</p>
                          {cve.ai_mitigation && (
                            <div style={{ margin: '10px 0', padding: 12, background: 'rgba(56,189,248,0.08)', border: '1px solid rgba(56,189,248,0.22)', borderRadius: 8 }}>
                              <p style={{ margin: '0 0 4px', fontSize: 12, color: '#38bdf8', fontWeight: 700 }}>🤖 AI Mitigation</p>
                              <p style={{ margin: '0 0 6px', fontSize: 12, color: '#d1d5db' }}>{renderValue(cve.ai_mitigation.summary) || 'No AI mitigation summary available'}</p>
                              {Array.isArray(cve.ai_mitigation.steps) && cve.ai_mitigation.steps.length > 0 ? (
                                <ul style={{ margin: 0, paddingLeft: 18, color: '#d1d5db', fontSize: 12 }}>
                                  {cve.ai_mitigation.steps.map((step, si) => (
                                    <li key={si} style={{ marginBottom: 4 }}>{renderValue(step)}</li>
                                  ))}
                                </ul>
                              ) : (
                                <p style={{ margin: 0, fontSize: 12, color: '#6b7280' }}>No mitigation steps available.</p>
                              )}
                            </div>
                          )}
                          {cve.ai_analysis && (
                            <div style={{ margin: '10px 0', padding: 12, background: 'rgba(96,165,250,0.08)', border: '1px solid rgba(96,165,250,0.22)', borderRadius: 8 }}>
                              <p style={{ margin: '0 0 4px', fontSize: 12, color: '#60a5fa', fontWeight: 700 }}>🤖 AI Analysis</p>
                              <p style={{ margin: '0 0 4px', fontSize: 12, color: '#d1d5db' }}><strong>Finding:</strong> {renderValue(cve.ai_analysis.finding)}</p>
                              <p style={{ margin: '0 0 4px', fontSize: 12, color: '#d1d5db' }}><strong>Reason:</strong> {renderValue(cve.ai_analysis.reason)}</p>
                              <p style={{ margin: 0, fontSize: 12, color: '#d1d5db' }}><strong>Recommendation:</strong> {renderValue(cve.ai_analysis.recommendation)}</p>
                            </div>
                          )}
                          <p style={{ margin: '0 0 8px', fontSize: 12, color: '#6b7280' }}>Published: {cve.published}</p>
                          {cve.exploit_available && cve.exploits?.length > 0 && (
                            <div style={{ background: 'rgba(127,29,29,0.2)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: 8, padding: 10, marginTop: 6 }}>
                              <p style={{ fontSize: 10, color: '#fca5a5', marginBottom: 5 }}>Known Exploits:</p>
                              {cve.exploits.map((ex, ei) => (
                                <div key={ei}><a href={ex.exploit_url || ex.url || '#'} target="_blank" rel="noreferrer" style={{ color: '#f87171', fontSize: 12 }}>{ex.title || ex.description || `Exploit ${ex.edb_id}`}</a></div>
                              ))}
                            </div>
                          )}
                        </td>
                      </motion.tr>
                    )}
                  </AnimatePresence>
                </React.Fragment>
              );
            })}
            {allCves.length === 0 && (
              <tr><td colSpan={7} style={{ padding: 28, textAlign: 'center', color: '#4b5563' }}>No vulnerabilities found.</td></tr>
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}

// ── History Tab ───────────────────────────────────────────────────────
function HistoryTab({ scanHistory, setScanHistory, selectedHistoryItem, setSelectedHistoryItem, expandedCve, setExpandedCve }) {
  const clearHistory = () => {
    setScanHistory([]);
    setSelectedHistoryItem(null);
    saveHistory([]);
  };

  const deleteItem = (id) => {
    setScanHistory(prev => {
      const updated = prev.filter(i => i.id !== id);
      saveHistory(updated);
      return updated;
    });
    if (selectedHistoryItem?.id === id) setSelectedHistoryItem(null);
  };

  if (scanHistory.length === 0) {
    return (
      <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 14, color: '#334155', minHeight: 300 }}>
        <History size={64} />
        <p style={{ fontSize: 14, letterSpacing: 2, margin: 0 }}>NO SCAN HISTORY YET</p>
        <p style={{ fontSize: 11, color: '#1e3a5f', margin: 0 }}>Completed scans will appear here</p>
      </div>
    );
  }

  return (
    <div style={{ display: 'flex', gap: 14, flex: 1, minHeight: 0 }}>
      {/* History list */}
      <div className="glass-card ui-history-panel" style={{ width: 280, flexShrink: 0, padding: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        <div style={{ padding: '14px 16px', borderBottom: '1px solid rgba(0,255,65,0.12)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 11, color: '#94a3b8', textTransform: 'uppercase', letterSpacing: 1 }}>Scan History ({scanHistory.length})</span>
          <button onClick={clearHistory} className="ui-btn" style={{ background: 'none', border: '1px solid rgba(255,255,255,0.1)', cursor: 'pointer', color: '#94a3b8', fontSize: 10, display: 'flex', alignItems: 'center', gap: 4, padding: '4px 8px', borderRadius: 6 }}>
            <Trash2 size={11} /> Clear
          </button>
        </div>
        <div style={{ overflowY: 'auto', flex: 1 }}>
          {scanHistory.map(item => (
            <div key={item.id}
              onClick={() => setSelectedHistoryItem(item)}
              style={{
                padding: '12px 16px', cursor: 'pointer', borderBottom: '1px solid rgba(75,85,99,0.25)',
                background: selectedHistoryItem?.id === item.id ? 'rgba(0,208,255,0.08)' : 'transparent',
                borderLeft: selectedHistoryItem?.id === item.id ? '3px solid #00ff41' : '3px solid transparent',
                transition: 'all 0.2s', position: 'relative'
              }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <span style={{ fontSize: 13, color: '#fff', fontWeight: 600 }}>{item.target}</span>
                <button onClick={e => { e.stopPropagation(); deleteItem(item.id); }}
                  style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#4b5563', padding: 0 }}>
                  <X size={12} />
                </button>
              </div>
              <div style={{ fontSize: 11, color: '#6b7280', marginTop: 3 }}>{item.time}</div>
              <div style={{ display: 'flex', gap: 8, marginTop: 6 }}>
                <span style={{ fontSize: 10, color: '#00ff41', background: 'rgba(0,255,65,0.12)', padding: '2px 6px', borderRadius: 3 }}>
                  {item.openPorts} ports
                </span>
                <span style={{ fontSize: 10, color: '#f59e0b', background: 'rgba(245,158,11,0.1)', padding: '2px 6px', borderRadius: 3 }}>
                  {item.cveCount} CVEs
                </span>
                {item.riskScore !== null && (
                  <span style={{ fontSize: 10, color: item.riskScore > 70 ? '#ff003c' : '#f59e0b', background: 'rgba(255,0,60,0.08)', padding: '2px 6px', borderRadius: 3 }}>
                    Risk {item.riskScore}
                  </span>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* History detail */}
      <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 14 }}>
        {selectedHistoryItem ? (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '4px 0' }}>
              <Eye size={14} style={{ color: '#00ff41' }} />
              <span style={{ fontSize: 12, color: '#00ff41' }}>Viewing scan: <strong>{selectedHistoryItem.target}</strong> — {selectedHistoryItem.time}</span>
            </div>
            <ResultsDashboard
              results={selectedHistoryItem.data}
              allCves={selectedHistoryItem.data?.hosts?.flatMap(h => h.open_ports?.flatMap(p => p.vulnerabilities || []) || []) || []}
              openPortsData={selectedHistoryItem.data?.hosts?.[0]?.open_ports?.map(p => ({ name: `${p.port}/${p.service || 'tcp'}`, value: 1 })) || []}
              expandedCve={expandedCve}
              setExpandedCve={setExpandedCve}
            />
          </motion.div>
        ) : (
          <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12, color: '#334155', minHeight: 200 }}>
            <ChevronRight size={40} />
            <p style={{ fontSize: 13, letterSpacing: 1, margin: 0 }}>SELECT A SCAN TO VIEW DETAILS</p>
          </div>
        )}
      </div>
    </div>
  );
}

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, info) {
    console.error('ErrorBoundary caught an error', error, info);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', padding: 24, background: '#0d1117', color: '#f8fafc' }}>
          <div style={{ maxWidth: 600, textAlign: 'center' }}>
            <h2 style={{ margin: 0, color: '#f87171' }}>Something went wrong.</h2>
            <p style={{ color: '#cbd5e1', marginTop: 12 }}>{this.state.error?.message || 'An unexpected UI error occurred.'}</p>
            <button onClick={() => this.setState({ hasError: false, error: null })} style={{ marginTop: 16, padding: '10px 16px', borderRadius: 8, background: '#2563eb', color: '#fff', border: 'none', cursor: 'pointer' }}>Reload UI</button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

function AppWrapper() {
  return (
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  );
}

export default AppWrapper;
