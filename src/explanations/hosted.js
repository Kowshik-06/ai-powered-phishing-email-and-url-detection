import axios from 'axios';
import { sanitizeEvidenceForHosted } from './evidence';

// The rest of the app also uses this local backend base URL.
export const API_BASE = 'http://localhost:5000';

export const CONSENT_CATEGORIES = [
  'input type',
  'final verdict',
  'decision source',
  'model prediction and raw score',
  'detector finding texts',
  'parsed hostname or domains',
  'basic feature counts',
  'coverage and limitations',
];

export function authHeaders() {
  let token = '';
  try {
    token = (typeof localStorage !== 'undefined' && localStorage.getItem('token')) || '';
  } catch {
    token = '';
  }
  return token ? { Authorization: 'Bearer ' + token } : {};
}

export async function fetchExplainConfig({ get = axios.get } = {}) {
  const response = await get(`${API_BASE}/explain/config`, { headers: authHeaders(), timeout: 8000 });
  return (response && response.data) || { enabled: false };
}

export async function requestHostedExplanation({ evidence, consent, post = axios.post } = {}) {
  if (consent !== true) {
    const error = new Error('consent_required');
    error.code = 'consent_required';
    throw error;
  }
  const payload = sanitizeEvidenceForHosted(evidence);
  try {
    const response = await post(
      `${API_BASE}/explain/hosted`,
      { consent: true, evidence: payload },
      { headers: authHeaders(), timeout: 20000 },
    );
    const data = response && response.data;
    const sections = data && data.sections;
    const required = ['whatWeFound', 'whyItMatters', 'whatToDoNext', 'whatWeCouldNotConfirm'];
    const valid = sections
      && typeof sections === 'object'
      && required.every((key) => typeof sections[key] === 'string' && sections[key].trim().length > 0);
    if (!valid) {
      const error = new Error('invalid_provider_output');
      error.code = 'invalid_provider_output';
      throw error;
    }
    return data;
  } catch (error) {
    if (error && error.code === 'invalid_provider_output') throw error;
    const status = error && error.response && error.response.status;
    const responseCode = error && error.response && error.response.data && error.response.data.error;
    const code = status === 401
      ? 'authentication_required'
      : (responseCode || (error && error.code) || 'provider_unavailable');
    const wrapped = new Error(code);
    wrapped.code = code;
    throw wrapped;
  }
}

const AI_ERROR_TEXT = {
  consent_required: 'consent was not recorded',
  provider_not_configured: 'the hosted provider is not configured',
  provider_timeout: 'the provider timed out',
  provider_rate_limited: 'the provider rate-limited the request',
  invalid_provider_output: 'the provider returned an invalid response',
  invalid_provider_response: 'the provider returned an unreadable response',
  provider_unavailable: 'the provider is unavailable',
  rate_limited: 'too many requests; try again later',
  authentication_required: 'your session is not authorized; sign in again',
  invalid_evidence: 'the sanitized evidence payload was rejected',
};

export function aiErrorMessage(code) {
  return AI_ERROR_TEXT[code] || 'the hosted provider could not be reached';
}
