import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import AdminDashboard from './AdminDashboard';
import { ResultCard } from './App';

let container;
let root;

beforeEach(() => {
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  jest.spyOn(axios, 'get').mockImplementation(url => {
    if (String(url).endsWith('/explain/config')) return Promise.resolve({ data: { enabled: false } });
    return Promise.reject(new Error('unexpected GET ' + url));
  });
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  jest.restoreAllMocks();
});

test('review remains the final verdict while the model score and prediction stay separate', async () => {
  await act(async () => {
    root.render(<ResultCard result={{
      type: 'review',
      threatCategory: 'Outside Training Range',
      riskPercentage: 96.61,
      modelRiskPercentage: 96.61,
      modelPrediction: 'phishing',
      decisionSource: 'outside-training-range',
      scoreMeaning: 'Uncalibrated model ensemble score; not a probability of maliciousness.',
      confidencePercentage: 93.23,
      urlLength: 116,
      hasHttps: true,
      suspiciousKeywords: 0,
      models: { randomForest: 77.88, histGradientBoosting: 99.84, deepLearning: 89.53, ensemble: 96.61 },
      reasons: ['Model input url_length=116 is outside the observed training range 13-96; manual review is required.'],
    }} onReport={() => {}}/>);
    await Promise.resolve();
  });

  expect(container.querySelector('h2').textContent).toBe('REVIEW');
  expect(container.querySelector('h2').className).toContain('text-amber-300');
  expect(container.textContent).toContain('Underlying model');
  expect(container.textContent).toContain('PHISHING');
  expect(container.textContent).toContain('FINAL RISK');
  expect(container.querySelector('.text-5xl').className).toContain('text-amber-300');
  expect(container.querySelector('.text-5xl').className).not.toContain('text-red-400');
  expect(container.textContent).toContain('Uncalibrated model ensemble score; not a probability of maliciousness.');
  expect(container.textContent).toContain('url_length=116 is outside the observed training range');
  expect(container.textContent).not.toContain('HIGH RISK');
});

test('missing URL-only fields are shown as unavailable, not as negative findings', async () => {
  await act(async () => {
    root.render(<ResultCard result={{
      type: 'phishing',
      riskPercentage: 72.08,
      confidencePercentage: 50,
      models: { ensemble: 72.08 },
      reasons: ['Credential language detected.'],
    }} onReport={() => {}} inputType="email"/>);
    await Promise.resolve();
  });

  expect(container.textContent).toContain('HTTPS-');
  expect(container.textContent).toContain('URL length-');
  expect(container.textContent).not.toContain('HTTPSNO');
});

test('admin overview uses backend statistics and shows the new-alert indicator', async () => {
  jest.spyOn(axios, 'get').mockImplementation(url => Promise.resolve(url.endsWith('/overview') ? {
    data: { totalUsers: 8, totalScans: 42, phishingDetections: 5, highRiskDetections: 3, criticalAlerts: 2, alertsAwaitingReview: 2, recentActivity: [], recentCriticalThreats: [] },
  } : { data: { items: [], total: 2, page: 1, limit: 1 } }));

  await act(async () => {
    root.render(<AdminDashboard token="test-session"/>);
    await new Promise(resolve => setTimeout(resolve, 0));
  });

  expect(container.textContent).toContain('Registered users');
  expect(container.textContent).toContain('42');
  expect(container.textContent).toContain('5');
  expect(container.textContent).toContain('Critical alerts (2 new)');
});

test('critical alerts view displays a persisted alert and acknowledges it', async () => {
  const alert = {
    id: 'alert-test-1',
    scanId: 'scan-test-1',
    username: 'test-user',
    scannedUrl: 'https://example.test/login?token=%5BREDACTED%5D',
    threatCategory: 'Credential Harvesting',
    riskPercentage: 98,
    verdict: 'phishing',
    severity: 'critical',
    timestamp: '2026-10-10T12:00:00.000Z',
    explanation: 'Confirmed phishing verdict corroborated by an @ symbol indicator.',
    status: 'new',
  };
  jest.spyOn(axios, 'get').mockImplementation(url => Promise.resolve(url.includes('/overview') ? {
    data: { totalUsers: 2, totalScans: 4, phishingDetections: 1, highRiskDetections: 1, criticalAlerts: 1, alertsAwaitingReview: 1, recentActivity: [], recentCriticalThreats: [alert] },
  } : { data: { items: [alert], total: 1, page: 1, limit: 25 } }));
  const patch = jest.spyOn(axios, 'patch').mockResolvedValue({ data: { ...alert, status: 'acknowledged' } });

  await act(async () => {
    root.render(<AdminDashboard token="test-session"/>);
    await new Promise(resolve => setTimeout(resolve, 0));
  });
  const alertsTab = [...container.querySelectorAll('nav button')].find(button => button.textContent.startsWith('Critical alerts'));
  await act(async () => {
    alertsTab.click();
    await new Promise(resolve => setTimeout(resolve, 0));
  });
  const alertRow = container.querySelector('ul button');
  expect(alertRow.textContent).toContain('Credential Harvesting');
  await act(async () => {
    alertRow.click();
    await new Promise(resolve => setTimeout(resolve, 0));
  });
  expect(container.textContent).toContain(alert.explanation);
  expect(container.textContent).toContain(alert.scannedUrl);
  const acknowledge = [...container.querySelectorAll('button')].find(button => button.textContent.includes('Acknowledge'));
  await act(async () => {
    acknowledge.click();
    await new Promise(resolve => setTimeout(resolve, 0));
  });
  expect(patch).toHaveBeenCalledWith('http://localhost:5000/admin/alerts/alert-test-1', { status: 'acknowledged' }, expect.any(Object));
  expect(container.textContent).toContain('acknowledged');
});

test('historical backfill requires confirmation and reports backend counts', async () => {
  let backfilled = false;
  const alert = { id: 'historical-alert', scanId: 'legacy-scan', username: 'archive-user', threatCategory: 'Credential Harvesting', riskPercentage: 98, verdict: 'phishing', severity: 'critical', timestamp: '2021-05-06T07:08:09.000Z', historical: true, status: 'new', explanation: 'Historical evidence qualified.' };
  jest.spyOn(window, 'confirm').mockReturnValue(true);
  jest.spyOn(axios, 'get').mockImplementation(url => Promise.resolve(url.includes('/overview') ? {
    data: { totalUsers: 2, totalScans: 42, phishingDetections: 9, highRiskDetections: 6, criticalAlerts: backfilled ? 1 : 0, alertsAwaitingReview: backfilled ? 1 : 0, recentActivity: [], recentCriticalThreats: [] },
  } : url.includes('/alerts?status=new&limit=1') ? {
    data: { items: [], total: backfilled ? 1 : 0, page: 1, limit: 1 },
  } : {
    data: { items: backfilled ? [alert] : [], total: backfilled ? 1 : 0, page: 1, limit: 25 },
  }));
  const post = jest.spyOn(axios, 'post').mockImplementation(() => {
    backfilled = true;
    return Promise.resolve({ data: { examined: 42, qualified: 9, created: 9, alreadyAlerted: 0, unevaluable: 4 } });
  });

  await act(async () => {
    root.render(<AdminDashboard token="test-session"/>);
    await new Promise(resolve => setTimeout(resolve, 0));
  });
  const alertsTab = [...container.querySelectorAll('nav button')].find(button => button.textContent.startsWith('Critical alerts'));
  await act(async () => {
    alertsTab.click();
    await new Promise(resolve => setTimeout(resolve, 0));
  });
  const backfillButton = [...container.querySelectorAll('button')].find(button => button.textContent === 'Backfill historical scans');
  await act(async () => {
    backfillButton.click();
    await new Promise(resolve => setTimeout(resolve, 0));
  });

  expect(window.confirm).toHaveBeenCalled();
  expect(post).toHaveBeenCalledWith('http://localhost:5000/admin/alerts/backfill', { confirm: true }, expect.any(Object));
  expect(container.textContent).toContain('examined 42, qualified 9, created 9, already alerted 0, unable to evaluate 4');
  expect(container.textContent).toContain('legacy-scan');
});
