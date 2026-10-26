import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { Activity, AlertTriangle, Check, ChevronLeft, ChevronRight, RefreshCw, Search, ShieldAlert, Users } from 'lucide-react';

const API = 'http://localhost:5000/admin';
const PAGE_SIZE = 25;
const auth = token => ({ headers: { Authorization: `Bearer ${token}` } });
const formatDate = value => value ? new Date(value).toLocaleString() : 'Not available';
const safe = value => value === null || value === undefined || value === '' ? 'Not available' : String(value);

function Stat({ label, value, icon: Icon, tone = 'text-cyan-300' }) {
  return <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
    <div className="flex justify-between items-center text-xs text-slate-500"><span>{label}</span><Icon size={16} className={tone}/></div>
    <div className={'mt-2 text-2xl font-bold ' + tone}>{value ?? 0}</div>
  </div>;
}

function TablePager({ page, total, onChange }) {
  const pages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  return <div className="flex items-center justify-between pt-3 text-sm text-slate-500">
    <span>{total} records · page {page} of {pages}</span>
    <div className="flex gap-2">
      <button type="button" aria-label="Previous page" disabled={page <= 1} onClick={() => onChange(page - 1)} className="p-2 rounded bg-slate-950 disabled:opacity-30"><ChevronLeft size={16}/></button>
      <button type="button" aria-label="Next page" disabled={page >= pages} onClick={() => onChange(page + 1)} className="p-2 rounded bg-slate-950 disabled:opacity-30"><ChevronRight size={16}/></button>
    </div>
  </div>;
}

function RecordDetails({ record, title = 'Scan details' }) {
  if (!record) return null;
  const excluded = new Set(['models', 'reasons', 'explanations', 'embeddedUrls', 'urls', 'urlResults', 'ocrUrls']);
  return <section className="mt-4 border border-slate-800 rounded-lg bg-slate-950 p-4" aria-label={title}>
    <h3 className="font-semibold text-slate-200 mb-3">{title}</h3>
    <dl className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-sm">
      {Object.entries(record).filter(([key, value]) => !excluded.has(key) && (typeof value !== 'object' || value === null)).map(([key, value]) =>
        <div key={key} className="min-w-0"><dt className="text-xs text-slate-500">{key}</dt><dd className="mt-1 text-slate-200 break-words">{safe(value)}</dd></div>
      )}
    </dl>
    {Array.isArray(record.reasons) && <div className="mt-3"><h4 className="text-xs text-slate-500">Detection reasons</h4><ul className="mt-1 space-y-1">{record.reasons.map((reason, index) => <li key={index} className="text-sm text-slate-200">{reason}</li>)}</ul></div>}
    {record.models && <div className="mt-3"><h4 className="text-xs text-slate-500">Model outputs</h4><dl className="mt-1 flex flex-wrap gap-3">{Object.entries(record.models).map(([name, value]) => <div key={name}><dt className="text-xs text-slate-500">{name}</dt><dd className="text-sm text-slate-200">{value}%</dd></div>)}</dl></div>}
    {record.explanations?.decision && <p className="mt-3 text-sm text-amber-200">{record.explanations.decision}</p>}
  </section>;
}

export default function AdminDashboard({ token, initialOverview }) {
  const [view, setView] = useState('overview');
  const [overview, setOverview] = useState(initialOverview || null);
  const [users, setUsers] = useState({ items: [], total: 0, page: 1 });
  const [scans, setScans] = useState({ items: [], total: 0, page: 1 });
  const [alerts, setAlerts] = useState({ items: [], total: 0, page: 1 });
  const [newAlerts, setNewAlerts] = useState(0);
  const [selectedUser, setSelectedUser] = useState(null);
  const [selectedScan, setSelectedScan] = useState(null);
  const [selectedAlert, setSelectedAlert] = useState(null);
  const [userSearch, setUserSearch] = useState('');
  const [scanFilters, setScanFilters] = useState({ username: '', verdict: '', type: '', risk: '', from: '', to: '' });
  const [alertStatus, setAlertStatus] = useState('new');
  const [backfillReport, setBackfillReport] = useState(null);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  useEffect(() => {
    let active = true;
    const refresh = async () => {
      try {
        const [stats, newItems] = await Promise.all([
          axios.get(`${API}/overview`, auth(token)),
          axios.get(`${API}/alerts?status=new&limit=1`, auth(token)),
        ]);
        if (active) {
          setOverview(stats.data);
          setNewAlerts(newItems.data.total || 0);
          setError('');
        }
      } catch (requestError) {
        if (active) setError(requestError.response?.data?.error || 'Unable to load admin overview.');
      }
    };
    refresh();
    const timer = window.setInterval(refresh, 30000);
    return () => { active = false; window.clearInterval(timer); };
  }, [token]);

  useEffect(() => {
    if (view !== 'users' || selectedUser) return undefined;
    let active = true;
    setLoading(true);
    const params = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE), search: userSearch });
    axios.get(`${API}/users?${params}`, auth(token)).then(response => {
      if (active) setUsers(response.data);
    }).catch(requestError => {
      if (active) setError(requestError.response?.data?.error || 'Unable to load users.');
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [token, view, selectedUser, userSearch, page]);

  useEffect(() => {
    if (view !== 'scans') return undefined;
    let active = true;
    setLoading(true);
    const params = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE) });
    Object.entries(scanFilters).forEach(([key, value]) => { if (value) params.set(key, value); });
    axios.get(`${API}/scans?${params}`, auth(token)).then(response => {
      if (active) setScans(response.data);
    }).catch(requestError => {
      if (active) setError(requestError.response?.data?.error || 'Unable to load scans.');
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [token, view, scanFilters, page]);

  useEffect(() => {
    if (view !== 'alerts') return undefined;
    let active = true;
    setLoading(true);
    const params = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE) });
    if (alertStatus) params.set('status', alertStatus);
    axios.get(`${API}/alerts?${params}`, auth(token)).then(response => {
      if (active) setAlerts(response.data);
    }).catch(requestError => {
      if (active) setError(requestError.response?.data?.error || 'Unable to load alerts.');
    }).finally(() => { if (active) setLoading(false); });
    return () => { active = false; };
  }, [token, view, alertStatus, page]);

  const changeView = next => {
    setSelectedUser(null);
    setSelectedScan(null);
    setSelectedAlert(null);
    setPage(1);
    setError('');
    setView(next);
  };

  const loadUserScans = async user => {
    setLoading(true);
    setError('');
    try {
      const response = await axios.get(`${API}/users/${encodeURIComponent(user.id)}/scans?page=1&limit=${PAGE_SIZE}`, auth(token));
      setSelectedUser({ ...user, scans: response.data });
    } catch (requestError) {
      setError(requestError.response?.data?.error || 'Unable to load user scan history.');
    } finally { setLoading(false); }
  };

  const updateAlert = async (alert, status) => {
    if (status === 'resolved' && !window.confirm('Resolve this critical alert?')) return;
    setLoading(true);
    setError('');
    try {
      const response = await axios.patch(`${API}/alerts/${encodeURIComponent(alert.id)}`, { status }, auth(token));
      setSelectedAlert(response.data);
      const list = await axios.get(`${API}/alerts?status=${encodeURIComponent(alertStatus)}&page=${page}&limit=${PAGE_SIZE}`, auth(token));
      setAlerts(list.data);
      const [stats, unread] = await Promise.all([
        axios.get(`${API}/overview`, auth(token)),
        axios.get(`${API}/alerts?status=new&limit=1`, auth(token)),
      ]);
      setOverview(stats.data);
      setNewAlerts(unread.data.total || 0);
    } catch (requestError) {
      setError(requestError.response?.data?.error || 'Unable to update alert.');
    } finally { setLoading(false); }
  };

  const backfillHistoricalAlerts = async () => {
    const confirmed = window.confirm('Evaluate existing scan history using the current critical-alert rules? Existing scans and alerts will be preserved.');
    if (!confirmed) return;
    setLoading(true);
    setError('');
    setBackfillReport(null);
    try {
      const response = await axios.post(`${API}/alerts/backfill`, { confirm: true }, auth(token));
      setBackfillReport(response.data);
      const params = new URLSearchParams({ page: String(page), limit: String(PAGE_SIZE) });
      if (alertStatus) params.set('status', alertStatus);
      const [list, stats, unread] = await Promise.all([
        axios.get(`${API}/alerts?${params}`, auth(token)),
        axios.get(`${API}/overview`, auth(token)),
        axios.get(`${API}/alerts?status=new&limit=1`, auth(token)),
      ]);
      setAlerts(list.data);
      setOverview(stats.data);
      setNewAlerts(unread.data.total || 0);
    } catch (requestError) {
      setError(requestError.response?.data?.error || 'Historical alert backfill failed.');
    } finally { setLoading(false); }
  };

  const nav = [['overview', 'Overview'], ['users', 'Users'], ['scans', 'Scan history'], ['alerts', `Critical alerts${newAlerts ? ` (${newAlerts} new)` : ''}`]];
  const stats = overview || {};

  return <div className="space-y-5" aria-label="Admin monitoring dashboard">
    <div className="flex flex-wrap items-start justify-between gap-3">
      <div><h2 className="text-xl font-bold text-white">Admin Monitoring</h2><p className="text-sm text-slate-500">System activity and confirmed threat alerts</p></div>
      <button type="button" onClick={() => window.location.reload()} className="inline-flex items-center gap-2 rounded-lg border border-slate-700 px-3 py-2 text-sm text-slate-300"><RefreshCw size={15}/>Refresh</button>
    </div>
    <nav className="flex flex-wrap gap-2 border-b border-slate-800 pb-3" aria-label="Admin sections">
      {nav.map(([id, label]) => <button key={id} type="button" onClick={() => changeView(id)} className={'rounded-lg px-3 py-2 text-sm font-semibold ' + (view === id ? 'bg-cyan-500 text-slate-950' : 'bg-slate-900 text-slate-400 hover:text-white')}>{label}</button>)}
    </nav>
    {error && <div role="alert" className="rounded-lg border border-red-500/40 bg-red-500/10 p-3 text-sm text-red-300">{error}</div>}
    {loading && <p role="status" className="text-xs text-slate-500">Loading admin data...</p>}

    {view === 'overview' && <div className="space-y-5">
      <div className="grid grid-cols-2 lg:grid-cols-3 gap-3">
        <Stat label="Registered users" value={stats.totalUsers} icon={Users}/>
        <Stat label="Scans performed" value={stats.totalScans} icon={Activity}/>
        <Stat label="Phishing detections" value={stats.phishingDetections} icon={ShieldAlert} tone="text-red-300"/>
        <Stat label="High-risk detections" value={stats.highRiskDetections} icon={AlertTriangle} tone="text-orange-300"/>
        <Stat label="Critical alerts" value={stats.criticalAlerts} icon={ShieldAlert} tone="text-amber-300"/>
        <Stat label="Awaiting review" value={stats.alertsAwaitingReview} icon={AlertTriangle} tone="text-amber-200"/>
      </div>
      {newAlerts > 0 && <button type="button" onClick={() => changeView('alerts')} className="w-full text-left rounded-lg border border-red-500/50 bg-red-500/10 p-4 text-red-200"><strong>{newAlerts} new critical alert{newAlerts === 1 ? '' : 's'}</strong><span className="block text-sm text-red-200/80">Open the alert queue to review confirmed threats.</span></button>}
      <div className="grid xl:grid-cols-2 gap-4">
        <section className="border border-slate-800 rounded-lg bg-slate-900/60 p-4"><h3 className="font-semibold text-slate-200 mb-3">Recent activity</h3>
          {stats.recentActivity?.length ? <ul className="divide-y divide-slate-800">{stats.recentActivity.map((scan, index) => <li key={scan.scanId || scan.id || index} className="py-3"><div className="flex justify-between gap-3 text-sm"><span className="text-slate-200">{safe(scan.username || scan.user)} · {safe(scan.scanType || 'legacy scan')}</span><span className="text-slate-400 uppercase">{safe(scan.type)}</span></div><div className="mt-1 text-xs text-slate-500">{formatDate(scan.timestamp)} · {safe(scan.scannedUrl || scan.url || scan.input)}</div></li>)}</ul> : <p className="text-sm text-slate-500">No scan activity yet.</p>}
        </section>
        <section className="border border-slate-800 rounded-lg bg-slate-900/60 p-4"><h3 className="font-semibold text-slate-200 mb-3">Recent critical threats</h3>
          {stats.recentCriticalThreats?.length ? <ul className="divide-y divide-slate-800">{stats.recentCriticalThreats.map(alert => <li key={alert.id} className="py-3"><button type="button" onClick={() => { setSelectedAlert(alert); changeView('alerts'); }} className="w-full text-left"><span className="text-sm font-semibold text-red-300">{safe(alert.username)} · {safe(alert.threatCategory)}</span><span className="block mt-1 text-xs text-slate-500">{formatDate(alert.timestamp)} · {safe(alert.status)}</span></button></li>)}</ul> : <p className="text-sm text-slate-500">No critical alerts.</p>}
        </section>
      </div>
    </div>}

    {view === 'users' && <section className="border border-slate-800 rounded-lg bg-slate-900/60 p-4">
      {selectedUser ? <>
        <button type="button" onClick={() => setSelectedUser(null)} className="text-sm text-cyan-300 mb-3">Back to users</button>
        <h3 className="text-lg font-bold text-white">{safe(selectedUser.name)} <span className="text-sm font-normal text-slate-500">({safe(selectedUser.role)})</span></h3>
        <p className="text-sm text-slate-400">ID {safe(selectedUser.id)} · {safe(selectedUser.email)} · {selectedUser.totalScans} scans</p>
        {selectedUser.scans?.items?.length ? <div className="mt-4 space-y-2">{selectedUser.scans.items.map(scan => <button key={scan.scanId || scan.id} type="button" onClick={() => setSelectedScan(scan)} className="block w-full rounded border border-slate-800 p-3 text-left text-sm hover:border-cyan-500/50">{safe(scan.scanType)} · {safe(scan.type)} · {safe(scan.scannedUrl || scan.url || scan.input)}<span className="block text-xs text-slate-500">{formatDate(scan.timestamp)}</span></button>)}</div> : <p className="mt-4 text-sm text-slate-500">No scan history.</p>}
        <RecordDetails record={selectedScan} title="Selected scan"/>
      </> : <>
        <div className="relative mb-4"><Search size={16} className="absolute left-3 top-3 text-slate-500"/><input aria-label="Search users" value={userSearch} onChange={event => { setUserSearch(event.target.value); setPage(1); }} placeholder="Search username" className="w-full rounded-lg border border-slate-700 bg-slate-950 py-2 pl-9 pr-3 text-sm text-slate-200"/></div>
        {users.items.length ? <div className="overflow-x-auto"><table className="w-full min-w-[650px] text-left text-sm"><thead className="text-xs uppercase text-slate-500"><tr>{['User ID','Name','Email','Role','Registered','Scans','History'].map(label => <th key={label} className="p-2">{label}</th>)}</tr></thead><tbody>{users.items.map(user => <tr key={user.id} className="border-t border-slate-800"><td className="p-2 text-xs text-slate-400">{safe(user.id)}</td><td className="p-2 text-slate-200">{safe(user.name)}</td><td className="p-2 text-slate-400">{safe(user.email)}</td><td className="p-2 uppercase text-cyan-300">{safe(user.role)}</td><td className="p-2 text-xs text-slate-500">{formatDate(user.registrationDate)}</td><td className="p-2">{user.totalScans}</td><td className="p-2"><button type="button" onClick={() => loadUserScans(user)} className="text-cyan-300">View scans</button></td></tr>)}</tbody></table></div> : <p className="text-sm text-slate-500">{loading ? 'Loading users...' : 'No users found.'}</p>}
        <TablePager page={users.page || page} total={users.total} onChange={setPage}/>
      </>}
    </section>}

    {view === 'scans' && <section className="border border-slate-800 rounded-lg bg-slate-900/60 p-4">
      <div className="grid grid-cols-2 lg:grid-cols-6 gap-2 mb-4">
        <input aria-label="Filter username" value={scanFilters.username} onChange={event => { setScanFilters({ ...scanFilters, username: event.target.value }); setPage(1); }} placeholder="Username" className="rounded border border-slate-700 bg-slate-950 p-2 text-sm"/>
        <select aria-label="Filter verdict" value={scanFilters.verdict} onChange={event => { setScanFilters({ ...scanFilters, verdict: event.target.value }); setPage(1); }} className="rounded border border-slate-700 bg-slate-950 p-2 text-sm"><option value="">All verdicts</option>{['phishing','suspicious','review','legitimate'].map(value => <option key={value}>{value}</option>)}</select>
        <select aria-label="Filter scan type" value={scanFilters.type} onChange={event => { setScanFilters({ ...scanFilters, type: event.target.value }); setPage(1); }} className="rounded border border-slate-700 bg-slate-950 p-2 text-sm"><option value="">All types</option>{['url','email','qr','screenshot','attachment'].map(value => <option key={value}>{value}</option>)}</select>
        <select aria-label="Filter risk level" value={scanFilters.risk} onChange={event => { setScanFilters({ ...scanFilters, risk: event.target.value }); setPage(1); }} className="rounded border border-slate-700 bg-slate-950 p-2 text-sm"><option value="">All risk</option>{['low','medium','high'].map(value => <option key={value}>{value}</option>)}</select>
        <input aria-label="From date" type="date" value={scanFilters.from} onChange={event => { setScanFilters({ ...scanFilters, from: event.target.value }); setPage(1); }} className="rounded border border-slate-700 bg-slate-950 p-2 text-sm"/>
        <input aria-label="To date" type="date" value={scanFilters.to} onChange={event => { setScanFilters({ ...scanFilters, to: event.target.value }); setPage(1); }} className="rounded border border-slate-700 bg-slate-950 p-2 text-sm"/>
      </div>
      {selectedScan && <RecordDetails record={selectedScan} title="Selected scan"/>}
      {scans.items.length ? <div className="mt-4 overflow-x-auto"><table className="w-full min-w-[700px] text-left text-sm"><thead className="text-xs uppercase text-slate-500"><tr>{['When','User','Type','Verdict','Score','Target',''].map(label => <th key={label} className="p-2">{label}</th>)}</tr></thead><tbody>{scans.items.map(scan => <tr key={scan.scanId || scan.id} className="border-t border-slate-800"><td className="p-2 text-xs text-slate-500">{formatDate(scan.timestamp)}</td><td className="p-2">{safe(scan.username || scan.user)}</td><td className="p-2 uppercase text-slate-400">{safe(scan.scanType)}</td><td className={'p-2 uppercase ' + (scan.type === 'review' ? 'text-amber-300' : scan.type === 'phishing' ? 'text-red-300' : 'text-slate-300')}>{safe(scan.type)}</td><td className="p-2">{safe(scan.riskPercentage)}%</td><td className="max-w-[300px] truncate p-2 text-xs text-slate-400">{safe(scan.scannedUrl || scan.url || scan.input)}</td><td className="p-2"><button type="button" onClick={() => setSelectedScan(scan)} className="text-cyan-300">Details</button></td></tr>)}</tbody></table></div> : <p className="mt-4 text-sm text-slate-500">{loading ? 'Loading scans...' : 'No scans match these filters.'}</p>}
      <TablePager page={scans.page || page} total={scans.total} onChange={setPage}/>
    </section>}

    {view === 'alerts' && <section className="border border-slate-800 rounded-lg bg-slate-900/60 p-4">
      <div className="flex flex-wrap items-center justify-between gap-3 mb-4"><h3 className="font-semibold text-white">Critical threat alerts <span className="text-xs text-amber-300">{newAlerts} new</span></h3><div className="flex flex-wrap items-center gap-2"><button type="button" disabled={loading} onClick={backfillHistoricalAlerts} className="rounded border border-amber-500/50 px-3 py-2 text-sm text-amber-200 disabled:opacity-50">Backfill historical scans</button><select aria-label="Filter alert status" value={alertStatus} onChange={event => { setAlertStatus(event.target.value); setPage(1); }} className="rounded border border-slate-700 bg-slate-950 p-2 text-sm"><option value="">All statuses</option>{['new','acknowledged','resolved'].map(value => <option key={value}>{value}</option>)}</select></div></div>
      {backfillReport && <p role="status" className="mb-4 rounded border border-cyan-500/30 bg-cyan-500/10 p-3 text-sm text-cyan-100">Historical backfill complete: examined {backfillReport.examined}, qualified {backfillReport.qualified}, created {backfillReport.created}, already alerted {backfillReport.alreadyAlerted}, unable to evaluate {backfillReport.unevaluable}.</p>}
      {alerts.items.length ? <div className="grid xl:grid-cols-2 gap-4"><ul className="space-y-2">{alerts.items.map(alert => <li key={alert.id}><button type="button" onClick={() => setSelectedAlert(alert)} className={'w-full rounded-lg border p-3 text-left ' + (selectedAlert?.id === alert.id ? 'border-amber-400/70 bg-amber-500/10' : 'border-slate-800 bg-slate-950')}><div className="flex justify-between gap-3"><span className="font-semibold text-red-300">{safe(alert.username)} · {safe(alert.threatCategory)}</span><span className="text-xs uppercase text-amber-200">{safe(alert.status)}</span></div><div className="mt-1 text-xs text-slate-400">{safe(alert.verdict)} · score {safe(alert.riskPercentage)} · {formatDate(alert.timestamp)}</div><div className="mt-1 text-xs text-slate-500">Scan: {safe(alert.scanId)}</div><div className="mt-1 truncate text-xs text-slate-500">{safe(alert.scannedUrl)}</div></button></li>)}</ul>
        {selectedAlert && <div className="rounded-lg border border-slate-800 bg-slate-950 p-4"><div className="flex items-center gap-2 text-red-300"><ShieldAlert size={18}/><h4 className="font-semibold">Critical alert</h4></div><p className="mt-3 text-sm text-slate-200">{selectedAlert.explanation}</p><p className="mt-2 break-words text-xs text-slate-400">{safe(selectedAlert.scannedUrl)}</p><p className="mt-2 text-xs text-slate-500">{safe(selectedAlert.username)} · {formatDate(selectedAlert.timestamp)} · {safe(selectedAlert.status)}</p><div className="mt-4 flex gap-2">{selectedAlert.status === 'new' && <button type="button" disabled={loading} onClick={() => updateAlert(selectedAlert, 'acknowledged')} className="inline-flex items-center gap-2 rounded bg-amber-400 px-3 py-2 text-sm font-semibold text-slate-950"><Check size={15}/>Acknowledge</button>}{selectedAlert.status === 'acknowledged' && <button type="button" disabled={loading} onClick={() => updateAlert(selectedAlert, 'resolved')} className="rounded bg-red-500 px-3 py-2 text-sm font-semibold text-white">Resolve</button>}</div></div>}
      </div> : <p className="text-sm text-slate-500">{loading ? 'Loading alerts...' : 'No alerts for this status.'}</p>}
      <TablePager page={alerts.page || page} total={alerts.total} onChange={setPage}/>
    </section>}
  </div>;
}