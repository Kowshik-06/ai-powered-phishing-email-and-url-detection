import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Shield, CheckCircle, XCircle, Activity, History, TrendingUp, Search, Upload, Mail, Link as LinkIcon, QrCode, Trash2, AlertTriangle, FileText, Globe, Image as ImageIcon, LogOut, Users } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

const API = 'http://localhost:5000';
const EMPTY = { type: null, riskPercentage: 0, confidencePercentage: 0, reasons: [], models: {} };
const auth = () => ({ headers: { Authorization: 'Bearer ' + localStorage.getItem('token') } });
const riskColor = r => r >= 70 ? 'text-red-400' : r >= 30 ? 'text-amber-400' : 'text-green-400';
const riskLevel = r => r >= 70 ? 'HIGH' : r >= 30 ? 'MEDIUM' : 'LOW';

function Login({ onLogin }) {
  const [register, setRegister] = useState(false), [username, setUsername] = useState(''), [password, setPassword] = useState(''), [error, setError] = useState('');
  const submit = async () => {
    try {
      const r = await axios.post(API + (register ? '/auth/register' : '/auth/login'), { username, password });
      if (register) { setRegister(false); setError('Account created. Sign in now.'); }
      else { localStorage.setItem('token', r.data.token); onLogin(r.data); }
    } catch (e) { setError(e.response?.data?.error || e.message); }
  };
  return <div className="min-h-screen bg-slate-950 text-slate-200 flex items-center justify-center p-5"><div className="w-full max-w-md bg-slate-900 border border-slate-800 rounded-2xl p-8">
    <div className="text-center mb-7"><Shield className="mx-auto text-green-400 w-14 h-14"/><h1 className="text-2xl font-black mt-3">PHISHING AI</h1><p className="text-slate-500 text-sm">Secure Threat Analysis Console</p></div>
    <input value={username} onChange={e => setUsername(e.target.value)} placeholder="Username" className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 mb-3"/>
    <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="Password (6+ chars)" className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 mb-4"/>
    <button onClick={submit} className="w-full p-3 rounded-lg bg-green-500 text-slate-950 font-black">{register ? 'CREATE ACCOUNT' : 'SIGN IN'}</button>
    {error && <p className="text-amber-300 text-sm mt-4">{error}</p>}
    <button onClick={() => { setRegister(!register); setError(''); }} className="w-full mt-4 text-cyan-400 text-sm">{register ? 'Already have an account? Sign in' : 'New here? Create account'}</button>
  </div></div>;
}

function ResultCard({ result, onReport }) {
  if (!result?.type) return <div className="h-full min-h-[420px] flex items-center justify-center border border-slate-800 rounded-2xl bg-slate-900/60 text-slate-600"><div className="text-center"><Shield className="mx-auto w-16 h-16 mb-4 opacity-30"/><p>Waiting for a scan</p></div></div>;
  const threat = result.type !== 'legitimate';
  return <div className={'border-2 ' + (threat ? 'border-red-500/60' : 'border-green-500/60') + ' rounded-2xl bg-slate-900/80 p-7 shadow-2xl'}>
    <div className="flex justify-between items-start"><div className="flex gap-4 items-center">{threat ? <XCircle className="w-14 h-14 text-red-400"/> : <CheckCircle className="w-14 h-14 text-green-400"/>}<div><h2 className={'text-2xl font-bold ' + (threat ? 'text-red-400' : 'text-green-400')}>{result.type.toUpperCase()}</h2><p className="text-slate-500 text-sm">{result.threatCategory || 'Threat assessment'}</p></div></div><div className={'text-right ' + riskColor(result.riskPercentage)}><div className="text-5xl font-black">{result.riskPercentage}%</div><div className="text-xs tracking-widest">{riskLevel(result.riskPercentage)} RISK</div></div></div>
    <div className="mt-7 grid grid-cols-2 md:grid-cols-4 gap-3">{[['Confidence', result.confidencePercentage + '%'], ['URL length', result.urlLength ?? '-'], ['HTTPS', result.hasHttps ? 'YES' : 'NO'], ['Keywords', result.suspiciousKeywords ?? '-']].map(([a,b]) => <div className="bg-slate-950 rounded-xl p-4" key={a}><div className="text-xs text-slate-600">{a}</div><div className="text-lg font-bold text-slate-200 mt-1">{b}</div></div>)}</div>
    {result.models && <div className="mt-6"><h3 className="text-sm font-bold text-cyan-400 mb-3">MODEL ENSEMBLE</h3><div className="grid grid-cols-2 md:grid-cols-4 gap-3">{Object.entries(result.models).map(([k,v]) => <div className="bg-slate-950 p-3 rounded-lg" key={k}><div className="text-xs text-slate-500 capitalize">{k.replace(/([A-Z])/g, ' $1')}</div><div className="font-bold text-cyan-300">{v}%</div></div>)}</div></div>}
    <div className="mt-6"><h3 className="text-sm font-bold text-cyan-400 mb-3">EXPLAINABLE AI — WHY?</h3><ul className="space-y-2">{(result.reasons || []).map((r,i) => <li key={i} className="text-sm text-slate-300 flex gap-2"><AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5"/>{r}</li>)}</ul></div>
    <button onClick={() => onReport(result)} className="mt-6 px-4 py-2 rounded-lg bg-cyan-500 text-slate-950 font-bold"><FileText size={15} className="inline mr-2"/>Export PDF Report</button>
  </div>;
}

export default function App() {
  const [user,setUser] = useState(null), [tab,setTab] = useState('dashboard'), [mode,setMode] = useState('url');
  const [url,setUrl] = useState(''), [email,setEmail] = useState(''), [file,setFile] = useState(null), [qr,setQr] = useState(null), [screen,setScreen] = useState(null), [domain,setDomain] = useState('');
  const [result,setResult] = useState(EMPTY), [extra,setExtra] = useState(null), [loading,setLoading] = useState(false), [error,setError] = useState(''), [history,setHistory] = useState([]), [metrics,setMetrics] = useState(null), [search,setSearch] = useState(''), [admin,setAdmin] = useState(null);
  const logout = () => { localStorage.removeItem('token'); setUser(null); };
  const load = async () => { try { const r = await Promise.all([axios.get(API+'/history',auth()), axios.get(API+'/metrics',auth())]); setHistory(r[0].data); setMetrics(r[1].data); if (user?.role === 'admin') { try { setAdmin((await axios.get(API+'/admin/overview',auth())).data); } catch {} } } catch (e) { if (e.response?.status === 401) logout(); } };
  useEffect(() => { const t=localStorage.getItem('token'); if(t) axios.get(API+'/auth/me',auth()).then(r=>setUser(r.data)).catch(logout); }, []);
  useEffect(() => { if(user) load(); }, [user]);
  const readFile = f => new Promise((ok,no) => { const r=new FileReader(); r.onload=()=>ok(r.result); r.onerror=no; r.readAsDataURL(f); });
  const scan = async () => {
    setLoading(true); setError(''); setExtra(null);
    try {
      let r;
      if(mode==='url') r=await axios.post(API+'/predict',{url},auth());
      else if(mode==='email') r=await axios.post(API+'/predict-email',{email},auth());
      else if(mode==='qr') r=await axios.post(API+'/predict-qr',{imageBase64:await readFile(qr)},auth());
      else if(mode==='attachment') r=await axios.post(API+'/analyze-attachment',{filename:file.name,fileBase64:await readFile(file)},auth());
      else if(mode==='screenshot') r=await axios.post(API+'/analyze-screenshot',{imageBase64:await readFile(screen)},auth());
      else { r=await axios.post(API+'/domain-intelligence',{domain},auth()); setExtra(r.data); return; }
      setResult(r.data); await load();
    } catch(e) { setError(e.response?.data?.error || e.message || 'Scan failed'); } finally { setLoading(false); }
  };
  const report = async data => { try { const r=await axios.post(API+'/report',data,auth()); const a=document.createElement('a'); a.href='data:application/pdf;base64,'+r.data.pdfBase64; a.download='phishing-threat-report.pdf'; a.click(); } catch(e) { setError('PDF report generation failed: '+e.message); } };
  const clearHistory = async () => { await axios.delete(API+'/history',auth()); load(); };
  if(!user) return <Login onLogin={setUser}/>;
  const filtered=history.filter(x=>(x.input||'').toLowerCase().includes(search.toLowerCase()));
  const stats={total:history.length,threats:history.filter(x=>['phishing','suspicious'].includes(x.type)).length,safe:history.filter(x=>x.type==='legitimate').length};
  const modes=[['url',LinkIcon,'URL'],['email',Mail,'EMAIL'],['qr',QrCode,'QR'],['attachment',FileText,'FILE'],['screenshot',ImageIcon,'SCREEN'],['domain',Globe,'DOMAIN']];
  return <div className="min-h-screen bg-slate-950 text-slate-200 flex">
    <aside className="w-64 hidden md:flex flex-col border-r border-slate-800 p-6"><div className="flex items-center gap-3 mb-10"><Shield className="text-green-400"/><div><b className="text-white">PHISHING</b><div className="text-green-400 text-xs">AI DETECTION</div></div></div>
      {[['dashboard',Activity,'Dashboard'],['history',History,'Scan History'],['analytics',TrendingUp,'Analytics'],['admin',Users,'Admin']].map(([id,I,n]) => id==='admin' && user.role!=='admin' ? null : <button key={id} onClick={()=>setTab(id)} className={'flex items-center gap-3 p-3 rounded-lg mb-2 ' + (tab===id ? 'bg-green-500/10 text-green-400' : 'text-slate-500 hover:text-slate-200')}><I size={18}/>{n}</button>)}
      <div className="mt-auto"><div className="text-xs text-slate-600 mb-3">Signed in as {user.username} ({user.role})</div><button onClick={logout} className="text-red-400 text-sm"><LogOut size={15} className="inline mr-2"/>Sign out</button></div>
    </aside>
    <main className="flex-1 p-5 md:p-10 max-w-[1500px] mx-auto w-full"><header className="mb-8"><div className="text-xs text-green-400 tracking-[.25em]">AI-POWERED PHISHING EMAIL AND URL DETECTION</div><h1 className="text-3xl md:text-4xl font-black text-white mt-2">Threat Analysis Console</h1></header>
      {tab==='dashboard' && <><div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-7">{[['TOTAL SCANS',stats.total],['THREATS',stats.threats],['SAFE',stats.safe]].map(([a,b])=><div className="bg-slate-900 border border-slate-800 rounded-xl p-5" key={a}><div className="text-xs text-slate-500">{a}</div><div className="text-3xl font-bold mt-1">{b}</div></div>)}</div>
        <div className="grid lg:grid-cols-2 gap-7"><section className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6"><div className="grid grid-cols-3 md:grid-cols-6 gap-2 mb-5">{modes.map(([id,I,n])=><button key={id} onClick={()=>{setMode(id);setResult(EMPTY);setExtra(null)}} className={'p-2 rounded-lg text-xs font-bold '+(mode===id?'bg-green-500 text-slate-950':'bg-slate-950 text-slate-500')}><I size={15} className="inline mr-1"/>{n}</button>)}</div>
          {mode==='url' && <input value={url} onChange={e=>setUrl(e.target.value)} onKeyDown={e=>e.key==='Enter'&&scan()} placeholder="https://example.com" className="w-full bg-slate-950 border border-slate-700 rounded-xl p-4"/>}
          {mode==='email' && <textarea value={email} onChange={e=>setEmail(e.target.value)} placeholder="Paste raw .eml content..." className="w-full h-64 bg-slate-950 border border-slate-700 rounded-xl p-4 font-mono text-sm"/>}
          {mode==='domain' && <input value={domain} onChange={e=>setDomain(e.target.value)} placeholder="example.com" className="w-full bg-slate-950 border border-slate-700 rounded-xl p-4"/>}
          {['qr','attachment','screenshot'].includes(mode) && <label className="h-64 border-2 border-dashed border-slate-700 rounded-xl flex flex-col items-center justify-center cursor-pointer"><Upload className="text-cyan-400 mb-3"/><span>{(mode==='qr'?qr:mode==='attachment'?file:screen)?.name || 'Choose a file'}</span><input type="file" accept={mode==='qr'||mode==='screenshot'?'image/*':'*/*'} className="hidden" onChange={e=>{const f=e.target.files[0]; if(mode==='qr')setQr(f); else if(mode==='attachment')setFile(f); else setScreen(f);}}/></label>}
          <button onClick={scan} disabled={loading} className="w-full mt-5 p-4 rounded-xl bg-green-500 text-slate-950 font-black disabled:opacity-50">{loading?'ANALYZING...':'EXECUTE THREAT SCAN'}</button>{error&&<div className="mt-4 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-300 text-sm">{error}</div>}{extra&&<pre className="mt-5 bg-slate-950 p-4 rounded-xl text-xs overflow-auto max-h-72">{JSON.stringify(extra,null,2)}</pre>}</section><ResultCard result={result} onReport={report}/></div></>}
      {tab==='history' && <section className="bg-slate-900 border border-slate-800 rounded-2xl p-6"><div className="flex justify-between mb-5"><h2 className="text-xl font-bold">Scan History</h2><button onClick={clearHistory} className="text-red-400 text-sm"><Trash2 size={16} className="inline mr-1"/>Clear</button></div><div className="relative mb-5"><Search className="absolute left-3 top-3 text-slate-600" size={18}/><input value={search} onChange={e=>setSearch(e.target.value)} placeholder="Search scans..." className="w-full bg-slate-950 border border-slate-700 rounded-lg p-3 pl-10"/></div><div className="overflow-auto"><table className="w-full text-sm"><thead><tr className="text-slate-500 border-b border-slate-800"><th className="text-left p-3">Type</th><th className="text-left p-3">Input</th><th className="text-left p-3">Risk</th><th className="text-left p-3">Time</th></tr></thead><tbody>{filtered.map(x=><tr className="border-b border-slate-800/60" key={x.id}><td className="p-3 uppercase text-cyan-400">{x.type}</td><td className="p-3 max-w-md truncate">{x.input}</td><td className={'p-3 '+(x.riskPercentage>=70?'text-red-400':'text-green-400')}>{x.riskPercentage}%</td><td className="p-3 text-slate-500">{new Date(x.timestamp).toLocaleString()}</td></tr>)}</tbody></table></div></section>}
      {tab==='analytics' && <section><div className="grid md:grid-cols-2 gap-7">{metrics&&Object.entries(metrics).filter(([_,m])=>m&&typeof m.accuracy==='number').map(([name,m])=><div className="bg-slate-900 border border-slate-800 rounded-2xl p-6" key={name}><h2 className="font-bold text-cyan-400 mb-5 capitalize">{name.replace(/([A-Z])/g,' $1')} Evaluation</h2><div className="grid grid-cols-2 gap-3">{[['Accuracy',m.accuracy],['Precision',m.precision],['Recall',m.recall],['F1',m.f1],['ROC-AUC',m.roc_auc]].map(([k,v])=><div className="bg-slate-950 p-4 rounded-lg" key={k}><div className="text-xs text-slate-500">{k}</div><div className="text-2xl font-bold">{(v*100).toFixed(1)}%</div></div>)}</div></div>)}</div>{metrics&&metrics.randomForest&&<div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 mt-7"><h2 className="font-bold text-cyan-400 mb-5">Model Comparison</h2><ResponsiveContainer width="100%" height={320}><BarChart data={['accuracy','precision','recall','f1','roc_auc'].map(k=>({metric:k.toUpperCase(),RandomForest:metrics.randomForest[k]*100,HistGradientBoosting:metrics.histGradientBoosting[k]*100,DeepLearning:metrics.deepLearning[k]*100}))}><CartesianGrid strokeDasharray="3 3" stroke="#1e293b"/><XAxis dataKey="metric" stroke="#64748b"/><YAxis domain={[0,100]} stroke="#64748b"/><Tooltip/><Bar dataKey="RandomForest"/><Bar dataKey="HistGradientBoosting"/><Bar dataKey="DeepLearning"/></BarChart></ResponsiveContainer></div>}</section>}
      {tab==='admin' && <section className="grid md:grid-cols-3 gap-5">{admin&&Object.entries(admin).map(([k,v])=><div key={k} className="bg-slate-900 border border-slate-800 rounded-xl p-6"><div className="text-xs text-slate-500 uppercase">{k}</div><div className="text-3xl font-black mt-2">{v}</div></div>)}</section>}
    </main>
  </div>;
}
