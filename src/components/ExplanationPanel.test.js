import React, { act } from 'react';
import { createRoot } from 'react-dom/client';
import axios from 'axios';
import ExplanationPanel from './ExplanationPanel';

const phishing = {
  type: 'phishing',
  threatCategory: 'Credential Harvesting',
  riskPercentage: 94.92,
  confidencePercentage: 89.84,
  url: 'https://fake-chatgpt.com/login?token=private-value',
  urlLength: 52,
  hasHttps: true,
  suspiciousKeywords: 1,
  specialChars: 1,
  models: { randomForest: 80.2, histGradientBoosting: 97.1, deepLearning: 90.3, ensemble: 94.92 },
  modelPrediction: 'phishing',
  modelRiskPercentage: 94.92,
  decisionSource: 'model',
  scoreMeaning: 'Uncalibrated model ensemble score; not a probability of maliciousness.',
  reasons: ['Multiple security/account-related keywords detected in the URL.'],
};

let container;
let root;

beforeEach(() => {
  localStorage.clear();
  container = document.createElement('div');
  document.body.appendChild(container);
  root = createRoot(container);
  jest.spyOn(axios, 'get').mockResolvedValue({ data: { enabled: false } });
});

afterEach(() => {
  act(() => root.unmount());
  container.remove();
  jest.restoreAllMocks();
  localStorage.clear();
});

async function renderPanel(result = phishing) {
  await act(async () => {
    root.render(<ExplanationPanel result={result} inputType="url" />);
    await Promise.resolve();
  });
}

function findButton(label) {
  return [...container.querySelectorAll('button')].find((button) => button.textContent === label);
}

test('defaults to Beginner, shows the four sections, and keeps the verdict and score while switching modes', async () => {
  await renderPanel();

  expect(container.textContent).toContain('EXPLANATION');
  expect(container.textContent).toContain('What we found');
  expect(container.textContent).toContain('Why it matters');
  expect(container.textContent).toContain('What to do next');
  expect(container.textContent).toContain('What we could not confirm');
  expect(container.textContent).toContain('Verdict:');
  expect(container.textContent).toContain('Phishing');
  expect(container.textContent).toContain('94.92%');
  expect(container.textContent).not.toContain('Technical evidence');

  await act(async () => {
    findButton('Expert').click();
  });

  expect(container.textContent).toContain('Technical evidence');
  expect(container.textContent).toContain('Verdict:');
  expect(container.textContent).toContain('Phishing');
  expect(container.textContent).toContain('94.92%');
  expect(localStorage.getItem('phishing.explanationMode')).toBe('expert');
});

test('remembers the expert mode on the next render without storing scanned content', async () => {
  localStorage.setItem('phishing.explanationMode', 'expert');
  await renderPanel();

  expect(container.textContent).toContain('Technical evidence');
  expect(localStorage.getItem('phishing.explanationMode')).toBe('expert');
  expect(JSON.stringify(localStorage)).not.toContain('fake-chatgpt.com');
});

test('shows a local-only notice when the hosted provider is not configured', async () => {
  await renderPanel();

  expect(container.textContent).toContain('Hosted AI explanation is unavailable or not configured');
  expect(container.textContent).toContain('generated locally');
  expect(findButton('Get AI explanation')).toBeUndefined();
});

test('requires explicit consent before sending sanitized evidence and renders the hosted sections', async () => {
  jest.spyOn(axios, 'get').mockResolvedValue({ data: { enabled: true, model: 'test-model' } });
  const post = jest.spyOn(axios, 'post').mockResolvedValue({
    data: {
      source: 'hosted',
      sections: {
        whatWeFound: 'AI found the verified signals.',
        whyItMatters: 'AI explains why they matter.',
        whatToDoNext: 'AI suggests what to do.',
        whatWeCouldNotConfirm: 'AI lists the unknowns.',
      },
    },
  });

  await renderPanel();

  let button = findButton('Get AI explanation');
  expect(button.disabled).toBe(true);
  await act(async () => { button.click(); });
  expect(post).not.toHaveBeenCalled();

  const checkbox = container.querySelector('input[type="checkbox"]');
  await act(async () => { checkbox.click(); });

  button = findButton('Get AI explanation');
  expect(button.disabled).toBe(false);
  await act(async () => {
    button.click();
    await Promise.resolve();
  });

  expect(post).toHaveBeenCalledTimes(1);
  const [url, body] = post.mock.calls[0];
  expect(url).toBe('http://localhost:5000/explain/hosted');
  expect(body.consent).toBe(true);
  expect(body.evidence.inputType).toBe('url');
  expect(body.evidence.observed.hostname).toBe('fake-chatgpt.com');
  expect(JSON.stringify(body.evidence)).not.toContain('private-value');
  expect(JSON.stringify(body.evidence)).not.toContain('/login');
  expect(container.textContent).toContain('AI found the verified signals.');
  expect(container.textContent).toContain('AI lists the unknowns.');
});

test('keeps the deterministic explanation when the hosted provider fails', async () => {
  jest.spyOn(axios, 'get').mockResolvedValue({ data: { enabled: true } });
  jest.spyOn(axios, 'post').mockRejectedValue({ response: { data: { error: 'provider_timeout' } } });

  await renderPanel();
  const checkbox = container.querySelector('input[type="checkbox"]');
  await act(async () => { checkbox.click(); });
  const button = findButton('Get AI explanation');
  await act(async () => {
    button.click();
    await Promise.resolve();
  });

  expect(container.textContent).toContain('Hosted explanation unavailable (the provider timed out)');
  expect(container.textContent).toContain('Strong phishing signals were found');
  expect(container.textContent).toContain('What we found');
});

test('treats an unreachable config endpoint as local-only instead of failing the panel', async () => {
  jest.spyOn(axios, 'get').mockRejectedValue(new Error('network down'));
  await renderPanel();

  expect(container.textContent).toContain('What we found');
  expect(container.textContent).toContain('Hosted AI explanation is unavailable or not configured');
});
