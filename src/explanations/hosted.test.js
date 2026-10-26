import { requestHostedExplanation } from './hosted';
import { buildEvidence } from './evidence';

const validSections = {
  whatWeFound: 'a',
  whyItMatters: 'b',
  whatToDoNext: 'c',
  whatWeCouldNotConfirm: 'd',
};

test('does not call the provider without explicit consent', async () => {
  const post = jest.fn();
  await expect(requestHostedExplanation({ evidence: {}, consent: false, post })).rejects.toMatchObject({ code: 'consent_required' });
  expect(post).not.toHaveBeenCalled();
});

test('sends only the sanitized evidence payload', async () => {
  const post = jest.fn().mockResolvedValue({ data: { sections: validSections } });
  const evidence = buildEvidence({
    type: 'phishing',
    riskPercentage: 90,
    url: 'https://example.com/private/path?token=secret-value',
    urlLength: 52,
    hasHttps: true,
    modelPrediction: 'phishing',
    modelRiskPercentage: 90,
    decisionSource: 'model',
    reasons: ['A verified finding.'],
  }, { inputType: 'url' });

  await requestHostedExplanation({ evidence, consent: true, post });

  const [url, body, options] = post.mock.calls[0];
  expect(url).toBe('http://localhost:5000/explain/hosted');
  expect(body.consent).toBe(true);
  expect(body.evidence.observed.hostname).toBe('example.com');
  expect(JSON.stringify(body.evidence)).not.toContain('/private/path');
  expect(JSON.stringify(body.evidence)).not.toContain('secret-value');
  expect(options.timeout).toBe(20000);
});

test('rejects incomplete provider output before displaying it', async () => {
  const post = jest.fn().mockResolvedValue({ data: { sections: { whatWeFound: 'only one' } } });
  await expect(requestHostedExplanation({ evidence: {}, consent: true, post })).rejects.toMatchObject({ code: 'invalid_provider_output' });
});

test('maps provider failures to a stable error code', async () => {
  const post = jest.fn().mockRejectedValue({ response: { data: { error: 'provider_rate_limited' } } });
  await expect(requestHostedExplanation({ evidence: {}, consent: true, post })).rejects.toMatchObject({ code: 'provider_rate_limited' });
});

test('maps an expired session to a sign-in message code', async () => {
  const post = jest.fn().mockRejectedValue({ response: { status: 401, data: { error: 'Authentication required' } } });
  await expect(requestHostedExplanation({ evidence: {}, consent: true, post })).rejects.toMatchObject({ code: 'authentication_required' });
});
