const express = require('express');

const VALID_SCAN_TYPES = new Set(['url', 'email', 'qr', 'screenshot', 'attachment']);
const VALID_VERDICTS = new Set(['legitimate', 'phishing', 'suspicious', 'review']);
const VALID_ALERT_STATUSES = new Set(['new', 'acknowledged', 'resolved']);
function configuredPercent(name, fallback) {
  const raw = process.env[name];
  if (typeof raw !== 'string' || !raw.trim()) return fallback;
  const value = Number(raw);
  return Number.isFinite(value) && value >= 0 && value <= 100 ? value : fallback;
}
const HIGH_RISK_SCORE = configuredPercent('HIGH_RISK_SCORE', 70);

function redactUrl(value) {
  if (typeof value !== 'string') return value;
  try {
    const parsed = new URL(value);
    if (parsed.username) parsed.username = '[REDACTED]';
    if (parsed.password) parsed.password = '[REDACTED]';
    for (const key of parsed.searchParams.keys()) {
      if (/token|key|secret|auth|session|password|passwd|email|user|code|otp|signature|jwt/i.test(key)) {
        parsed.searchParams.set(key, '[REDACTED]');
      }
    }
    return parsed.toString();
  } catch {
    return value;
  }
}

function redactText(value) {
  return value.replace(/https?:\/\/[^\s<>"']+/gi, (match) => redactUrl(match));
}

function safeValue(value, key = '') {
  if (Array.isArray(value)) return value.map((item) => safeValue(item));
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([childKey, childValue]) => {
      return [childKey, safeValue(childValue, childKey)];
    }));
  }
  if (typeof value !== 'string') return value;
  if (/^(url|input|scannedUrl|decodedData)$/i.test(key)) return redactUrl(value);
  return redactText(value);
}

function inferScanType(scan) {
  if (VALID_SCAN_TYPES.has(scan.scanType)) return scan.scanType;
  if (Object.hasOwn(scan, 'decodedData')) return 'qr';
  if (Object.hasOwn(scan, 'ocrText') || Object.hasOwn(scan, 'ocrUrls')) return 'screenshot';
  if (Object.hasOwn(scan, 'filename') || Object.hasOwn(scan, 'extension')) return 'attachment';
  if (Object.hasOwn(scan, 'sender') || Object.hasOwn(scan, 'subject') || Object.hasOwn(scan, 'headerChecks')) return 'email';
  if (typeof scan.url === 'string' || typeof scan.scannedUrl === 'string') return 'url';
  return VALID_SCAN_TYPES.has(scan.type) ? scan.type : null;
}

function safeScan(scan) {
  const result = safeValue(scan);
  if (!result.scanId && result.id) result.scanId = String(result.id);
  if (!result.scanType) result.scanType = inferScanType(scan);
  if (!result.username && result.user) result.username = result.user;
  if (!result.userId && result.user) result.userId = result.user;
  return result;
}

function userIdentifier(user) {
  return user.id || user.userId || user.username;
}

function userScanOwner(scan) {
  return scan.userId || scan.user || scan.username;
}

function parsePage(query) {
  const page = query.page === undefined ? 1 : Number(query.page);
  const limit = query.limit === undefined ? 25 : Number(query.limit);
  if (!Number.isInteger(page) || page < 1 || !Number.isInteger(limit) || limit < 1 || limit > 100) {
    return null;
  }
  return { page, limit };
}

function parseDate(value) {
  if (value === undefined) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function paginated(items, page, limit) {
  const start = (page - 1) * limit;
  return { items: items.slice(start, start + limit), total: items.length, page, limit };
}

function createAdminRouter({ auth, requireAdmin, read, write, usersFile, historyFile, alertsFile, backfillHistoricalAlerts }) {
  const router = express.Router();
  router.use(auth, requireAdmin);

  router.get('/overview', (req, res) => {
    const users = read(usersFile);
    const scans = read(historyFile);
    const alerts = read(alertsFile);
    const phishingDetections = scans.filter((scan) => scan.type === 'phishing').length;
    const highRiskDetections = scans.filter((scan) => {
      return ['phishing', 'suspicious'].includes(scan.type) && Number(scan.riskPercentage) >= HIGH_RISK_SCORE;
    }).length;
    const newestFirst = [...scans].sort((a, b) => Date.parse(b.timestamp || 0) - Date.parse(a.timestamp || 0));
    const recentThreats = newestFirst.filter((scan) => ['phishing', 'suspicious'].includes(scan.type)).slice(0, 8);
    res.json({
      totalUsers: users.length,
      totalScans: scans.length,
      phishingDetections,
      highRiskDetections,
      criticalAlerts: alerts.filter((alert) => alert.severity === 'critical').length,
      alertsAwaitingReview: alerts.filter((alert) => alert.status === 'new').length,
      threats: scans.filter((scan) => ['phishing', 'suspicious'].includes(scan.type)).length,
      attachments: scans.filter((scan) => inferScanType(scan) === 'attachment').length,
      emails: scans.filter((scan) => inferScanType(scan) === 'email').length,
      urls: scans.filter((scan) => inferScanType(scan) === 'url').length,
      qr: scans.filter((scan) => inferScanType(scan) === 'qr').length,
      recentActivity: newestFirst.slice(0, 8).map(safeScan),
      recentThreats: recentThreats.map(safeScan),
      recentCriticalThreats: [...alerts]
        .sort((a, b) => Date.parse(b.timestamp || 0) - Date.parse(a.timestamp || 0))
        .slice(0, 8)
        .map(safeScan),
    });
  });

  router.get('/users', (req, res) => {
    const pageInfo = parsePage(req.query);
    const search = String(req.query.search || '').trim().toLowerCase();
    if (!pageInfo || search.length > 100) return res.status(400).json({ error: 'Invalid pagination or search parameters.' });
    const scans = read(historyFile);
    const users = read(usersFile)
      .filter((user) => !search || String(user.username || '').toLowerCase().includes(search))
      .map((user) => {
        const id = userIdentifier(user);
        return {
          id,
          username: user.username,
          name: user.name || user.username,
          email: user.email || null,
          role: user.role || 'user',
          registrationDate: user.createdAt || null,
          totalScans: scans.filter((scan) => userScanOwner(scan) === id || userScanOwner(scan) === user.username).length,
        };
      });
    res.json(paginated(users, pageInfo.page, pageInfo.limit));
  });

  router.get('/users/:userId', (req, res) => {
    const user = read(usersFile).find((entry) => userIdentifier(entry) === req.params.userId || entry.username === req.params.userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    const id = userIdentifier(user);
    const scans = read(historyFile).filter((scan) => userScanOwner(scan) === id || userScanOwner(scan) === user.username);
    res.json({
      id,
      username: user.username,
      name: user.name || user.username,
      email: user.email || null,
      role: user.role || 'user',
      registrationDate: user.createdAt || null,
      totalScans: scans.length,
      recentScans: scans.slice(0, 10).map(safeScan),
    });
  });

  router.get('/users/:userId/scans', (req, res) => {
    const pageInfo = parsePage(req.query);
    if (!pageInfo) return res.status(400).json({ error: 'Invalid pagination parameters.' });
    const user = read(usersFile).find((entry) => userIdentifier(entry) === req.params.userId || entry.username === req.params.userId);
    if (!user) return res.status(404).json({ error: 'User not found.' });
    const id = userIdentifier(user);
    const scans = read(historyFile)
      .filter((scan) => userScanOwner(scan) === id || userScanOwner(scan) === user.username)
      .sort((a, b) => Date.parse(b.timestamp || 0) - Date.parse(a.timestamp || 0))
      .map(safeScan);
    res.json(paginated(scans, pageInfo.page, pageInfo.limit));
  });

  router.get('/scans', (req, res) => {
    const pageInfo = parsePage(req.query);
    const { username, verdict, type, risk, from, to } = req.query;
    const startDate = parseDate(from);
    const endDate = parseDate(to);
    if (!pageInfo || (username && String(username).length > 100) ||
        (verdict && !VALID_VERDICTS.has(String(verdict))) ||
        (type && !VALID_SCAN_TYPES.has(String(type))) ||
        (risk && !['low', 'medium', 'high'].includes(String(risk))) ||
        (from && !startDate) || (to && !endDate) ||
        (startDate && endDate && startDate > endDate)) {
      return res.status(400).json({ error: 'Invalid scan filters or pagination parameters.' });
    }
    const filtered = read(historyFile).filter((scan) => {
      const score = Number(scan.riskPercentage) || 0;
      const timestamp = Date.parse(scan.timestamp || '');
      return (!username || String(scan.username || scan.user || scan.userId || '').toLowerCase().includes(String(username).toLowerCase())) &&
        (!verdict || scan.type === verdict) && (!type || inferScanType(scan) === type) &&
        (!risk || (risk === 'high' ? score >= HIGH_RISK_SCORE : risk === 'medium' ? score >= 30 && score < HIGH_RISK_SCORE : score < 30)) &&
        (!startDate || timestamp >= startDate.getTime()) && (!endDate || timestamp <= endDate.getTime());
    }).sort((a, b) => Date.parse(b.timestamp || 0) - Date.parse(a.timestamp || 0)).map(safeScan);
    res.json(paginated(filtered, pageInfo.page, pageInfo.limit));
  });

  router.get('/scans/:scanId', (req, res) => {
    const scan = read(historyFile).find((entry) => String(entry.scanId || entry.id) === req.params.scanId);
    if (!scan) return res.status(404).json({ error: 'Scan not found.' });
    res.json(safeScan(scan));
  });

  router.get('/alerts', (req, res) => {
    const pageInfo = parsePage(req.query);
    const { status, severity } = req.query;
    if (!pageInfo || (status && !VALID_ALERT_STATUSES.has(String(status))) ||
        (severity && !['critical'].includes(String(severity)))) {
      return res.status(400).json({ error: 'Invalid alert filters or pagination parameters.' });
    }
    const alerts = read(alertsFile)
      .filter((alert) => (!status || alert.status === status) && (!severity || alert.severity === severity))
      .sort((a, b) => Date.parse(b.timestamp || 0) - Date.parse(a.timestamp || 0))
      .map(safeScan);
    res.json(paginated(alerts, pageInfo.page, pageInfo.limit));
  });

  router.post('/alerts/backfill', (req, res) => {
    if (req.body?.confirm !== true) return res.status(400).json({ error: 'Explicit confirmation is required.' });
    try {
      res.json(backfillHistoricalAlerts());
    } catch (error) {
      console.error(`[critical-alert] Historical backfill failed: ${error.message}`);
      res.status(500).json({ error: 'Historical alert backfill failed; existing alert records were preserved.' });
    }
  });

  router.get('/alerts/:alertId', (req, res) => {
    const alert = read(alertsFile).find((entry) => entry.id === req.params.alertId);
    if (!alert) return res.status(404).json({ error: 'Alert not found.' });
    res.json(safeScan(alert));
  });

  router.patch('/alerts/:alertId', (req, res) => {
    const status = req.body && req.body.status;
    if (!['acknowledged', 'resolved'].includes(status)) {
      return res.status(400).json({ error: 'Status must be acknowledged or resolved.' });
    }
    const alerts = read(alertsFile);
    const alert = alerts.find((entry) => entry.id === req.params.alertId);
    if (!alert) return res.status(404).json({ error: 'Alert not found.' });
    alert.status = status;
    alert.updatedAt = new Date().toISOString();
    alert.updatedBy = req.user.username;
    write(alertsFile, alerts);
    res.json(safeScan(alert));
  });

  return router;
}

module.exports = { createAdminRouter, inferScanType, redactUrl, safeScan };