const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { safeScan } = require('./admin');

let dataDir;
let appServer;
let mlServer;
let api;
let adminToken;
let userToken;
let userId;
let adminId;
let mockPort;

test('legacy scan records are enriched without exposing sensitive URL parameters', () => {
  const legacy = safeScan({
    id: 'legacy-scan-id', type: 'review', user: 'legacy-user',
    url: 'https://example.test/path?token=legacy-secret',
  });
  assert.equal(legacy.scanId, 'legacy-scan-id');
  assert.equal(legacy.scanType, 'url');
  assert.equal(legacy.userId, 'legacy-user');
  assert.equal(legacy.username, 'legacy-user');
  assert.equal(JSON.stringify(legacy).includes('legacy-secret'), false);
});

function listen(server) {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => {
      server.removeListener('error', reject);
      resolve(server.address().port);
    });
  });
}

async function request(route, { method = 'GET', token, body, setupToken } = {}) {
  const headers = {};
  if (token) headers.Authorization = `Bearer ${token}`;
  if (setupToken) headers['x-admin-setup-token'] = setupToken;
  if (body !== undefined) headers['Content-Type'] = 'application/json';
  const response = await fetch(`${api}${route}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await response.json();
  return { status: response.status, json };
}

test('admin monitoring APIs enforce authorization, persist scans, and create evidence-based alerts', async (t) => {
  dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'phishing-admin-test-'));
  process.env.DATA_DIR = dataDir;
  process.env.ADMIN_SETUP_TOKEN = 'test-only-setup-token';

  mlServer = http.createServer((req, res) => {
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
      const data = JSON.parse(body || '{}');
      const isReview = String(data.url || '').includes('review-case');
      const result = req.url === '/predict-email' ? {
        type: 'legitimate', riskPercentage: 5, confidencePercentage: 90, subject: 'Test email',
        reasons: [],
      } : req.url === '/predict-qr' ? {
        type: 'legitimate', riskPercentage: 0, confidencePercentage: 90, decodedData: 'https://example.test/qr',
        reasons: [],
      } : req.url === '/analyze-screenshot' ? {
        type: 'review', riskPercentage: 0, confidencePercentage: 0, ocrText: 'No text', reasons: ['No readable text could be extracted.'],
      } : req.url === '/analyze-attachment' ? {
        type: 'suspicious', riskPercentage: 55, confidencePercentage: 10, filename: 'test.txt', reasons: ['Manual review required.'],
      } : isReview ? {
        type: 'review',
        riskPercentage: 98.5,
        confidencePercentage: 97,
        modelPrediction: 'phishing',
        modelRiskPercentage: 98.5,
        decisionSource: 'outside-training-range',
        threatCategory: 'Outside Training Range',
        reasons: ['URL length is outside the observed training range.'],
      } : {
        type: 'phishing',
        riskPercentage: 98,
        confidencePercentage: 96,
        modelPrediction: 'phishing',
        modelRiskPercentage: 98,
        threatCategory: 'Credential Harvesting',
        reasons: ['URL contains an @ symbol, which can hide the true destination.'],
      };
      result.url = data.url;
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(result));
    });
  });

  mockPort = await listen(mlServer);
  process.env.ML_PORT = String(mockPort);
  const { app, createAlert, read, write } = require('./server');
  const port = await new Promise((resolve, reject) => {
    appServer = app.listen(0, '127.0.0.1', () => resolve(appServer.address().port));
    appServer.once('error', reject);
  });
  api = `http://127.0.0.1:${port}`;

  t.after(async () => {
    await new Promise((resolve) => mlServer.close(resolve));
    if (appServer) await new Promise((resolve) => appServer.close(resolve));
    fs.rmSync(dataDir, { recursive: true, force: true });
    delete process.env.DATA_DIR;
    delete process.env.ML_PORT;
    delete process.env.ADMIN_SETUP_TOKEN;
  });

  const registration = await request('/auth/register', {
    method: 'POST', body: { username: 'first-admin', password: 'first-pass-123', role: 'admin' },
  });
  assert.equal(registration.status, 200);
  assert.equal(registration.json.role, 'user');

  const deniedSetup = await request('/auth/admin-setup', {
    method: 'POST', setupToken: 'wrong-token', body: { username: 'first-admin' },
  });
  assert.equal(deniedSetup.status, 403);

  const promoted = await request('/auth/admin-setup', {
    method: 'POST', setupToken: process.env.ADMIN_SETUP_TOKEN, body: { username: 'first-admin' },
  });
  assert.equal(promoted.status, 200);
  assert.equal(promoted.json.role, 'admin');
  assert.equal(JSON.stringify(promoted.json).includes('hash'), false);

  const secondSetup = await request('/auth/admin-setup', {
    method: 'POST', setupToken: process.env.ADMIN_SETUP_TOKEN, body: { username: 'first-admin' },
  });
  assert.equal(secondSetup.status, 409);

  const adminLogin = await request('/auth/login', {
    method: 'POST', body: { username: 'first-admin', password: 'first-pass-123' },
  });
  adminToken = adminLogin.json.token;
  adminId = adminLogin.json.userId;
  assert.ok(adminToken);
  assert.equal(JSON.stringify(adminLogin.json).includes('hash'), false);

  const userRegistration = await request('/auth/register', {
    method: 'POST', body: { username: 'regular-user', password: 'regular-pass-123' },
  });
  assert.equal(userRegistration.json.role, 'user');
  const userLogin = await request('/auth/login', {
    method: 'POST', body: { username: 'regular-user', password: 'regular-pass-123' },
  });
  userToken = userLogin.json.token;
  userId = userLogin.json.userId;

  const unauthorized = await request('/admin/overview');
  assert.equal(unauthorized.status, 401);
  const forbidden = await request('/admin/overview', { token: userToken });
  assert.equal(forbidden.status, 403);
  const userBackfill = await request('/admin/alerts/backfill', {
    method: 'POST', token: userToken, body: { confirm: true },
  });
  assert.equal(userBackfill.status, 403);
  const unconfirmedBackfill = await request('/admin/alerts/backfill', {
    method: 'POST', token: adminToken, body: {},
  });
  assert.equal(unconfirmedBackfill.status, 400);

  const scanResponse = await request('/predict', {
    method: 'POST', token: userToken,
    body: { url: 'https://evil.example/login?token=topsecret&email=user@example.com', userId: adminId },
  });
  assert.equal(scanResponse.status, 200);
  assert.equal(scanResponse.json.type, 'phishing');
  const records = read(path.join(dataDir, 'scan_history.json'));
  const saved = records[0];
  assert.equal(saved.scanType, 'url');
  assert.equal(saved.userId, userId);
  assert.equal(saved.username, 'regular-user');
  assert.equal(saved.type, 'phishing');
  assert.ok(saved.scanId);

  const userHistory = await request('/history', { token: userToken });
  assert.equal(userHistory.status, 200);
  assert.ok(userHistory.json.every((scan) => scan.userId === userId || scan.user === 'regular-user'));
  assert.equal(JSON.stringify(userHistory.json).includes('topsecret'), false);
  const userScans = await request(`/admin/users/${encodeURIComponent(userId)}/scans`, { token: adminToken });
  assert.equal(userScans.status, 200);
  assert.equal(userScans.json.total, 1);
  assert.equal(userScans.json.items[0].userId, userId);

  const otherScanRoutes = [
    ['/predict-email', { email: 'Subject: Test\n\nHello' }, 'email'],
    ['/predict-qr', { imageBase64: 'dGVzdA==' }, 'qr'],
    ['/analyze-screenshot', { imageBase64: 'dGVzdA==' }, 'screenshot'],
    ['/analyze-attachment', { filename: 'test.txt', fileBase64: 'dGVzdA==' }, 'attachment'],
  ];
  for (const [route, body, scanType] of otherScanRoutes) {
    const response = await request(route, { method: 'POST', token: userToken, body: { ...body, userId: adminId } });
    assert.equal(response.status, 200);
    const persisted = read(path.join(dataDir, 'scan_history.json')).find(scan => scan.scanType === scanType);
    assert.ok(persisted, `${scanType} scan should persist`);
    assert.equal(persisted.userId, userId);
    assert.equal(persisted.username, 'regular-user');
  }

  const adminScans = await request('/admin/scans?verdict=phishing&type=url', { token: adminToken });
  assert.equal(adminScans.status, 200);
  const publicScan = adminScans.json.items.find((scan) => scan.scanId === saved.scanId);
  assert.ok(publicScan);
  assert.ok(publicScan.url.includes('token=%5BREDACTED%5D') || publicScan.url.includes('token=[REDACTED]'));
  assert.equal(JSON.stringify(publicScan).includes('topsecret'), false);
  assert.equal(JSON.stringify(publicScan).includes('user@example.com'), false);
  const scanDetails = await request(`/admin/scans/${encodeURIComponent(saved.scanId)}`, { token: adminToken });
  assert.equal(scanDetails.status, 200);
  assert.equal(scanDetails.json.scanType, 'url');
  const userList = await request('/admin/users', { token: adminToken });
  assert.equal(userList.status, 200);
  assert.ok(userList.json.items.every((user) => !Object.hasOwn(user, 'hash')));
  assert.ok(userList.json.items.every((user) => !Object.hasOwn(user, 'token')));

  const beforeReviewAlerts = (await request('/admin/alerts?status=new', { token: adminToken })).json.total;
  const reviewResponse = await request('/predict', {
    method: 'POST', token: userToken, body: { url: 'https://review-case.example/' },
  });
  assert.equal(reviewResponse.json.type, 'review');
  const afterReviewAlerts = (await request('/admin/alerts?status=new', { token: adminToken })).json.total;
  assert.equal(afterReviewAlerts, beforeReviewAlerts);

  const newAlerts = await request('/admin/alerts?status=new&severity=critical', { token: adminToken });
  assert.equal(newAlerts.status, 200);
  assert.equal(newAlerts.json.total, 1);
  const alert = newAlerts.json.items[0];
  assert.equal(alert.verdict, 'phishing');
  assert.equal(alert.scanId, saved.scanId);
  assert.equal(alert.severity, 'critical');
  assert.equal(alert.status, 'new');
  assert.ok(Number.isFinite(Date.parse(alert.timestamp)));
  assert.ok(alert.explanation.includes('corroborated'));
  assert.ok(alert.explanation.includes('score 98'));
  const scoreOnly = createAlert({ ...saved, scanId: 'score-only-scan', reasons: [], riskPercentage: 99 });
  assert.equal(scoreOnly, null);
  assert.equal(createAlert({ ...saved, scanId: 'trusted-only-scan', type: 'legitimate', decisionSource: 'trusted-domain-override' }), null);
  assert.equal(createAlert({ ...saved, scanId: 'missing-confidence', confidencePercentage: undefined }), null);
  assert.equal(createAlert({ ...saved, scanId: 'missing-score', riskPercentage: undefined }), null);
  const emailEvidenceAlert = createAlert({
    ...saved,
    scanId: 'email-evidence-scan',
    scanType: 'email',
    reasons: ['Urgency/pressure language detected.', 'Credential or verification language detected.'],
  });
  assert.ok(emailEvidenceAlert);
  assert.equal(emailEvidenceAlert.severity, 'critical');
  const beforeDuplicate = read(path.join(dataDir, 'alerts.json')).length;
  const duplicate = createAlert(saved);
  assert.equal(duplicate.scanId, saved.scanId);
  assert.equal(read(path.join(dataDir, 'alerts.json')).length, beforeDuplicate);

  const acknowledged = await request(`/admin/alerts/${alert.id}`, {
    method: 'PATCH', token: adminToken, body: { status: 'acknowledged' },
  });
  assert.equal(acknowledged.status, 200);
  assert.equal(acknowledged.json.status, 'acknowledged');
  const resolved = await request(`/admin/alerts/${alert.id}`, {
    method: 'PATCH', token: adminToken, body: { status: 'resolved' },
  });
  assert.equal(resolved.status, 200);
  assert.equal(resolved.json.status, 'resolved');

  const overview = await request('/admin/overview', { token: adminToken });
  assert.equal(overview.status, 200);
  assert.equal(overview.json.totalUsers, 2);
  assert.equal(overview.json.totalScans, 6);
  assert.equal(overview.json.phishingDetections, 1);
  assert.equal(overview.json.criticalAlerts, 2);
  assert.equal(overview.json.alertsAwaitingReview, 1);
  const invalidPage = await request('/admin/scans?page=0', { token: adminToken });
  assert.equal(invalidPage.status, 400);

  const historyFile = path.join(dataDir, 'scan_history.json');
  const backupFile = `${historyFile}.backup`;
  fs.renameSync(historyFile, backupFile);
  fs.mkdirSync(historyFile);
  let scanAfterWriteFailure;
  try {
    scanAfterWriteFailure = await request('/predict', {
      method: 'POST', token: userToken, body: { url: 'https://write-failure.example/' },
    });
  } finally {
    fs.rmSync(historyFile, { recursive: true, force: true });
    fs.renameSync(backupFile, historyFile);
  }
  assert.equal(scanAfterWriteFailure.status, 200);
  assert.equal(scanAfterWriteFailure.json.type, 'phishing');

  await new Promise((resolve, reject) => appServer.close(error => error ? reject(error) : resolve()));
  delete require.cache[require.resolve('./server')];
  const restarted = require('./server');
  await new Promise((resolve, reject) => {
    appServer = restarted.app.listen(0, '127.0.0.1', () => resolve());
    appServer.once('error', reject);
  });
  api = `http://127.0.0.1:${appServer.address().port}`;
  const loginAfterRestart = await request('/auth/login', {
    method: 'POST', body: { username: 'first-admin', password: 'first-pass-123' },
  });
  assert.equal(loginAfterRestart.status, 200);
  adminToken = loginAfterRestart.json.token;
  const persistedResolved = await request('/admin/alerts?status=resolved', { token: adminToken });
  assert.equal(persistedResolved.json.total, 1);
  assert.equal(persistedResolved.json.items[0].scanId, saved.scanId);
  assert.equal(persistedResolved.json.items[0].status, 'resolved');
  const persistedNew = await request('/admin/alerts?status=new', { token: adminToken });
  assert.equal(persistedNew.json.total, 1);
  assert.equal(persistedNew.json.items[0].status, 'new');

  const historicalTimestamp = '2021-05-06T07:08:09.000Z';
  const historyBeforeBackfill = read(path.join(dataDir, 'scan_history.json'));
  const existingAlertsBeforeBackfill = read(path.join(dataDir, 'alerts.json'));
  const legacyAlreadyAlerted = {
    id: 'pre-existing-alert', scanId: 'legacy-already-alerted', verdict: 'phishing',
    severity: 'critical', status: 'acknowledged', timestamp: historicalTimestamp,
  };
  write(path.join(dataDir, 'alerts.json'), [legacyAlreadyAlerted, ...existingAlertsBeforeBackfill]);
  const historicalRows = [
    { id: 'legacy-qualified', user: 'archive-user', type: 'phishing', riskPercentage: 98, confidencePercentage: 88, models: { randomForest: null, histGradientBoosting: 95, deepLearning: 92, ensemble: 94 }, reasons: ['URL contains an @ symbol, which can hide the true destination.'], url: 'https://synthetic.example/path', timestamp: historicalTimestamp },
    { id: 'legacy-already-alerted', type: 'phishing', riskPercentage: 98, confidencePercentage: 88, models: { randomForest: 91, histGradientBoosting: 95, deepLearning: 92 }, reasons: ['URL contains an @ symbol, which can hide the true destination.'], url: 'https://synthetic.example/already', timestamp: historicalTimestamp },
    { id: 'legacy-review', type: 'review', riskPercentage: 99, confidencePercentage: 99, decisionSource: 'outside-training-range', reasons: ['URL contains an @ symbol, which can hide the true destination.'], timestamp: historicalTimestamp },
    { id: 'legacy-score-only', type: 'phishing', riskPercentage: 99, confidencePercentage: 99, models: { randomForest: 99, histGradientBoosting: 99 }, reasons: [], timestamp: historicalTimestamp },
    { id: 'legacy-missing-confidence', type: 'phishing', riskPercentage: 99, models: { randomForest: 99, histGradientBoosting: 99 }, reasons: ['URL contains an @ symbol, which can hide the true destination.'], timestamp: historicalTimestamp },
    { id: 'legacy-null-risk', type: 'phishing', riskPercentage: null, confidencePercentage: 99, reasons: ['URL contains an @ symbol, which can hide the true destination.'], timestamp: historicalTimestamp },
    { id: 'legacy-low-score', type: 'phishing', riskPercentage: 94, confidencePercentage: 99, reasons: ['URL contains an @ symbol, which can hide the true destination.'], timestamp: historicalTimestamp },
    { id: 'legacy-disagreement', type: 'phishing', riskPercentage: 99, confidencePercentage: 99, models: { randomForest: 10, histGradientBoosting: 99 }, reasons: ['URL contains an @ symbol, which can hide the true destination.'], timestamp: historicalTimestamp },
    { id: 'legacy-unrecognized-reason', type: 'phishing', riskPercentage: 99, confidencePercentage: 99, reasons: ['No readable text was detected.'], timestamp: historicalTimestamp },
  ];
  write(path.join(dataDir, 'scan_history.json'), [...historicalRows, ...historyBeforeBackfill]);

  const firstBackfill = await request('/admin/alerts/backfill', {
    method: 'POST', token: adminToken, body: { confirm: true },
  });
  assert.equal(firstBackfill.status, 200);
  assert.equal(firstBackfill.json.examined, historicalRows.length + historyBeforeBackfill.length);
  assert.equal(firstBackfill.json.qualified, 3);
  assert.equal(firstBackfill.json.created, 1);
  assert.equal(firstBackfill.json.alreadyAlerted, 2);
  assert.equal(firstBackfill.json.unevaluable, 3);
  const newHistoricalAlerts = await request('/admin/alerts?status=new', { token: adminToken });
  const historicalAlert = newHistoricalAlerts.json.items.find(item => item.scanId === 'legacy-qualified');
  assert.ok(historicalAlert);
  assert.equal(historicalAlert.verdict, 'phishing');
  assert.equal(historicalAlert.severity, 'critical');
  assert.equal(historicalAlert.historical, true);
  assert.equal(historicalAlert.timestamp, historicalTimestamp);
  assert.ok(Number.isFinite(Date.parse(historicalAlert.alertCreatedAt)));
  assert.equal(newHistoricalAlerts.json.items.some(item => item.scanId === 'legacy-review'), false);
  assert.equal(newHistoricalAlerts.json.items.some(item => item.scanId === 'legacy-score-only'), false);
  assert.equal(read(path.join(dataDir, 'scan_history.json')).length, historicalRows.length + historyBeforeBackfill.length);
  assert.deepEqual(read(path.join(dataDir, 'scan_history.json')), [...historicalRows, ...historyBeforeBackfill]);
  const firstAlertCount = read(path.join(dataDir, 'alerts.json')).length;
  assert.equal(read(path.join(dataDir, 'alerts.json')).find(item => item.scanId === 'legacy-already-alerted').status, 'acknowledged');

  const secondBackfill = await request('/admin/alerts/backfill', {
    method: 'POST', token: adminToken, body: { confirm: true },
  });
  assert.equal(secondBackfill.status, 200);
  assert.equal(secondBackfill.json.qualified, 3);
  assert.equal(secondBackfill.json.created, 0);
  assert.equal(secondBackfill.json.alreadyAlerted, 3);
  assert.equal(read(path.join(dataDir, 'alerts.json')).length, firstAlertCount);

  const acknowledgedHistorical = await request(`/admin/alerts/${historicalAlert.id}`, {
    method: 'PATCH', token: adminToken, body: { status: 'acknowledged' },
  });
  assert.equal(acknowledgedHistorical.json.status, 'acknowledged');
  await new Promise((resolve, reject) => appServer.close(error => error ? reject(error) : resolve()));
  delete require.cache[require.resolve('./server')];
  const persistedApp = require('./server').app;
  await new Promise((resolve, reject) => {
    appServer = persistedApp.listen(0, '127.0.0.1', () => resolve());
    appServer.once('error', reject);
  });
  api = `http://127.0.0.1:${appServer.address().port}`;
  const relogin = await request('/auth/login', {
    method: 'POST', body: { username: 'first-admin', password: 'first-pass-123' },
  });
  assert.equal(relogin.status, 200);
  const persistedHistoricalAlerts = await request('/admin/alerts?status=acknowledged', { token: relogin.json.token });
  const persistedHistoricalAlert = persistedHistoricalAlerts.json.items.find(item => item.scanId === 'legacy-qualified');
  assert.ok(persistedHistoricalAlert);
  assert.equal(persistedHistoricalAlert.historical, true);
  assert.equal(persistedHistoricalAlert.timestamp, historicalTimestamp);
  assert.equal(persistedHistoricalAlert.status, 'acknowledged');
});