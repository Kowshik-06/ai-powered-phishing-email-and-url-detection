// Shared evidence representation.
//
// The detector is the only authority for the verdict and risk score. This module
// only normalises the fields the detector already returns so the rule-based
// explanation engine, the UI, and the optional hosted adapter can reuse them.
//
// Missing values stay missing. They are recorded as unknowns and are never
// converted into a negative finding (for example, an absent HTTPS field is not
// reported as "does not use HTTPS").

export const EVIDENCE_SCHEMA_VERSION = 1;

const INPUT_TYPES = new Set(['url', 'email', 'qr', 'attachment', 'screenshot', 'domain', 'unavailable', 'unknown']);
const VERDICTS = new Set(['phishing', 'legitimate', 'suspicious', 'review', 'unavailable', 'unknown']);

const HOSTED_OBSERVED_KEYS = [
  'hostname', 'domain', 'urlLength', 'hasHttps', 'suspiciousKeywords', 'specialChars',
  'senderDomain', 'replyToDomain', 'domainMismatch', 'urlCount',
  'extension', 'sizeBytes', 'embeddedUrlCount', 'highestEmbeddedUrlRisk',
  'decodedKind', 'ocrUrlCount', 'ocrTextAvailable',
  'dnsAvailable', 'resolvedIpCount', 'rdapAvailable', 'virusTotalAvailable', 'indicators',
];

const HOSTNAME_KEYS = new Set(['hostname', 'domain', 'senderDomain', 'replyToDomain']);

function has(object, key) {
  return Object.prototype.hasOwnProperty.call(object || {}, key);
}

export function safeText(value, max = 400) {
  if (typeof value !== 'string') return null;
  const cleaned = value
    // eslint-disable-next-line no-control-regex
    .replace(/[\u0000-\u001f\u007f]+/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  if (!cleaned) return null;
  if (cleaned.length <= max) return cleaned;
  return cleaned.slice(0, Math.max(0, max - 1)).trim() + '…';
}

export function safeNumber(value) {
  if (value === null || value === undefined || value === '') return null;
  const number = Number(value);
  return Number.isFinite(number) ? number : null;
}

export function safeHostname(value) {
  const text = safeText(value, 253);
  if (!text) return null;
  const host = text.toLowerCase().replace(/\.$/, '');
  return /^[a-z0-9.-]{1,253}$/.test(host) && host.includes('.') ? host : null;
}

export function normalizeVerdict(value) {
  if (typeof value !== 'string') return null;
  const verdict = value.trim().toLowerCase();
  return VERDICTS.has(verdict) && verdict !== 'unknown' ? verdict : null;
}

export function hostFromUrl(value) {
  const text = safeText(value, 2048);
  if (!text) return null;
  try {
    const withScheme = /^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : 'https://' + text;
    const host = new URL(withScheme).hostname.toLowerCase().replace(/\.$/, '');
    return /^[a-z0-9.-]{1,253}$/.test(host) ? host : null;
  } catch {
    return null;
  }
}

export function domainFromAddress(value) {
  const text = safeText(value, 320);
  if (!text) return null;
  const match = text.match(/@([a-z0-9.-]+\.[a-z]{2,})/i);
  if (!match) return null;
  const domain = match[1].toLowerCase().replace(/\.$/, '');
  return /^[a-z0-9.-]{1,253}$/.test(domain) ? domain : null;
}

export function inferInputType(result) {
  if (!result || typeof result !== 'object') return 'unknown';
  if (result.domainAnalysis || (has(result, 'domain') && has(result, 'rdap') && has(result, 'resolvedIps'))) return 'domain';
  if (result.scanType === 'qr' || has(result, 'decodedData')) return 'qr';
  if (has(result, 'ocrText') || has(result, 'ocrUrls') || result.scanType === 'screenshot') return 'screenshot';
  if (has(result, 'filename') || has(result, 'extension')) return 'attachment';
  if (has(result, 'sender') || has(result, 'subject') || has(result, 'headerChecks')) return 'email';
  if (typeof result.url === 'string' || typeof result.urlLength === 'number' || has(result, 'models')) return 'url';
  return 'unknown';
}

function emptyEvidence(inputType, verdict, unknownText) {
  return {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    inputType: INPUT_TYPES.has(inputType) ? inputType : 'unknown',
    verdict: normalizeVerdict(verdict) || 'unknown',
    decisionSource: 'unknown',
    model: null,
    ruleFindings: [],
    observed: {},
    coverage: { level: 'none', analyzed: [], notAnalyzed: [], limitations: [] },
    unknown: [unknownText],
    disagreement: null,
    meta: { riskPercentage: null, confidencePercentage: null, threatCategory: null, scoreMeaning: null },
    unavailable: verdict === 'unavailable',
  };
}

export function buildEvidence(result, options = {}) {
  if (!result || typeof result !== 'object') {
    return emptyEvidence(options.inputType || 'unknown', 'unavailable', 'No scan result was available.');
  }
  const inferred = inferInputType(result);
  const inputType = INPUT_TYPES.has(options.inputType) ? options.inputType : inferred;
  const verdict = normalizeVerdict(result.type) || (inputType === 'unavailable' ? 'unavailable' : 'unknown');
  const ruleFindings = collectRuleFindings(result);
  const observed = collectObserved(result, inputType);
  const model = collectModel(result, inputType);
  // A failed scan must never inherit the coverage of the input type it was
  // trying to analyze. Claiming that URL/email evidence was examined when the
  // detector returned no result would be fabricated evidence.
  const coverageType = verdict === 'unavailable' ? 'unavailable' : inputType;
  const coverage = coverageFor(result, coverageType);
  const decisionSource = result.decisionSource || derivedDecisionSource(result, inputType);
  const disagreement = model && model.prediction && model.prediction !== verdict
    ? { modelPrediction: model.prediction, verdict, overridden: true }
    : null;

  return {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    inputType,
    verdict,
    decisionSource,
    model,
    ruleFindings,
    observed,
    coverage,
    unknown: unknownsFor(result, coverageType),
    disagreement,
    meta: {
      riskPercentage: safeNumber(result.riskPercentage),
      confidencePercentage: safeNumber(result.confidencePercentage),
      threatCategory: safeText(result.threatCategory, 80),
      scoreMeaning: safeText(result.scoreMeaning, 240),
    },
    unavailable: verdict === 'unavailable',
  };
}

function collectRuleFindings(result) {
  const findings = [];
  const seen = new Set();
  const push = (value, source) => {
    const text = safeText(value, 300);
    if (!text || seen.has(text)) return;
    seen.add(text);
    findings.push({ text, source });
  };
  if (result.explanations && result.explanations.decision) push(result.explanations.decision, 'decision');
  if (Array.isArray(result.explanations && result.explanations.heuristic)) {
    result.explanations.heuristic.forEach((text) => push(text, 'rule'));
  }
  if (Array.isArray(result.reasons)) result.reasons.forEach((text) => push(text, 'detector'));
  return findings.slice(0, 20);
}

function headerPresent(value) {
  if (typeof value !== 'string') return null;
  return !/^not present$/i.test(value.trim());
}

function put(observed, key, value) {
  if (value === null || value === undefined || value === '') return;
  if (typeof value === 'string') {
    const text = safeText(value, HOSTNAME_KEYS.has(key) ? 253 : 300);
    if (text) observed[key] = text;
    return;
  }
  if (typeof value === 'number' && Number.isFinite(value)) {
    observed[key] = value;
    return;
  }
  if (typeof value === 'boolean') {
    observed[key] = value;
    return;
  }
  if (Array.isArray(value) && value.length) {
    const items = value.slice(0, 10).map((item) => safeText(item, 80)).filter(Boolean);
    if (items.length) observed[key] = items;
  }
}

function collectObserved(result, inputType) {
  const observed = {};
  const hostname = hostFromUrl(result.url)
    || hostFromUrl(result.decodedData)
    || hostFromUrl(result.scannedUrl)
    || (result.domain ? hostFromUrl(result.domain) : null);
  if (hostname) observed.hostname = safeHostname(hostname) || hostname;

  if (inputType === 'url') {
    put(observed, 'urlLength', safeNumber(result.urlLength));
    put(observed, 'hasHttps', typeof result.hasHttps === 'boolean' ? result.hasHttps : null);
    put(observed, 'suspiciousKeywords', safeNumber(result.suspiciousKeywords));
    put(observed, 'specialChars', safeNumber(result.specialChars));
  } else if (inputType === 'email') {
    const senderDomain = domainFromAddress(result.sender);
    const replyToDomain = domainFromAddress(result.replyTo);
    put(observed, 'senderDomain', senderDomain);
    put(observed, 'replyToDomain', replyToDomain);
    // Only compare when both domains are actually present. Missing domains are
    // unknown, not a "no mismatch" finding.
    if (senderDomain && replyToDomain) put(observed, 'domainMismatch', senderDomain !== replyToDomain);
    put(observed, 'urlCount', safeNumber(result.urlCount));
    put(observed, 'emailTextModelScore', safeNumber(result.emailTextModelScore));
    const headers = result.headerChecks || {};
    put(observed, 'spfHeaderPresent', headerPresent(headers.spf));
    put(observed, 'dkimHeaderPresent', headerPresent(headers.dkim));
    put(observed, 'dmarcHeaderPresent', headerPresent(headers.dmarc));
    if (Array.isArray(result.urls) && result.urls.length) {
      const risks = result.urls.map((item) => safeNumber(item && item.riskPercentage)).filter((value) => value !== null);
      if (risks.length) observed.highestEmbeddedUrlRisk = Math.max(...risks);
    }
  } else if (inputType === 'qr') {
    const decodedIsUrl = typeof result.decodedData === 'string' && /^https?:\/\//i.test(result.decodedData);
    put(observed, 'decodedKind', result.decodedData ? (decodedIsUrl ? 'url' : 'text') : null);
    put(observed, 'urlLength', safeNumber(result.urlLength));
    put(observed, 'hasHttps', typeof result.hasHttps === 'boolean' ? result.hasHttps : null);
  } else if (inputType === 'attachment') {
    put(observed, 'extension', safeText(result.extension, 16));
    put(observed, 'sizeBytes', safeNumber(result.sizeBytes));
    if (Array.isArray(result.embeddedUrls) && result.embeddedUrls.length) {
      observed.embeddedUrlCount = result.embeddedUrls.length;
      const risks = result.embeddedUrls.map((item) => safeNumber(item && item.riskPercentage)).filter((value) => value !== null);
      if (risks.length) observed.highestEmbeddedUrlRisk = Math.max(...risks);
    }
  } else if (inputType === 'screenshot') {
    put(observed, 'width', safeNumber(result.width));
    put(observed, 'height', safeNumber(result.height));
    put(observed, 'edgeDensity', safeNumber(result.edgeDensity));
    put(observed, 'ocrUrlCount', Array.isArray(result.ocrUrls) ? result.ocrUrls.length : null);
    put(observed, 'ocrTextAvailable', typeof result.ocrText === 'string' && result.ocrText.trim().length > 0);
    if (result.screenshotIndicators && typeof result.screenshotIndicators === 'object') {
      const active = Object.keys(result.screenshotIndicators).filter((key) => result.screenshotIndicators[key]);
      put(observed, 'indicators', active);
    }
    if (Array.isArray(result.urlResults) && result.urlResults.length) {
      observed.embeddedUrlCount = result.urlResults.length;
      const risks = result.urlResults.map((item) => safeNumber(item && item.riskPercentage)).filter((value) => value !== null);
      if (risks.length) observed.highestEmbeddedUrlRisk = Math.max(...risks);
    }
  } else if (inputType === 'domain') {
    put(observed, 'domain', safeHostname(result.domain) || safeText(result.domain, 253));
    put(observed, 'dnsAvailable', typeof result.dnsAvailable === 'boolean' ? result.dnsAvailable : null);
    put(observed, 'resolvedIpCount', Array.isArray(result.resolvedIps) ? result.resolvedIps.length : null);
    put(observed, 'rdapAvailable', !!result.rdap);
    put(observed, 'virusTotalAvailable', !!result.virusTotal);
  } else if (inputType === 'unavailable') {
    put(observed, 'errorMessage', safeText(result.message, 200));
  }
  return observed;
}

function collectModel(result, inputType) {
  if (!result) return null;
  const hasUrlModel = has(result, 'models') || result.modelPrediction || safeNumber(result.modelRiskPercentage) !== null;
  if (hasUrlModel) {
    const components = Object.entries(result.models || {})
      .filter(([name, value]) => name !== 'ensemble' && safeNumber(value) !== null)
      .slice(0, 6)
      .map(([name, value]) => ({ name: safeText(name, 40), score: safeNumber(value) }))
      .filter((component) => component.name);
    return {
      role: 'final',
      prediction: normalizeVerdict(result.modelPrediction),
      score: safeNumber(result.modelRiskPercentage) !== null
        ? safeNumber(result.modelRiskPercentage)
        : (result.models ? safeNumber(result.models.ensemble) : null),
      calibrated: false,
      scoreMeaning: safeText(result.scoreMeaning, 240) || 'Uncalibrated model ensemble score; not a probability of maliciousness.',
      components,
    };
  }
  if (inputType === 'email' && safeNumber(result.emailTextModelScore) !== null) {
    return {
      role: 'component',
      prediction: null,
      score: safeNumber(result.emailTextModelScore),
      calibrated: false,
      scoreMeaning: 'Email text model score (uncalibrated); the final email risk also includes rule and URL signals.',
      components: [],
    };
  }
  return null;
}

function derivedDecisionSource(result, inputType) {
  if (inputType === 'email') return 'hybrid-rules';
  if (inputType === 'attachment') return 'rules-and-embedded-url';
  if (inputType === 'screenshot') return 'rules-and-ocr-url';
  if (inputType === 'domain') return 'informational';
  if (inputType === 'unavailable') return 'unavailable';
  if (inputType === 'qr') return result.decisionSource || (result.models ? 'model' : 'rules');
  if (result.models) return 'model';
  return 'unknown';
}

function coverageFor(result, inputType) {
  const coverage = { level: 'partial', analyzed: [], notAnalyzed: [], limitations: [] };
  if (Array.isArray(result && result.limitations)) {
    coverage.limitations.push(...result.limitations.map((text) => safeText(text, 300)).filter(Boolean));
  }
  if (inputType === 'url') {
    coverage.analyzed = ['URL structure and character patterns', 'Trained URL model scoring', 'Built-in trusted-domain list check'];
    coverage.notAnalyzed = ['Page content', 'Live reputation and blocklist services (unless configured)', 'Destination server behavior', 'Whether the site is currently compromised'];
    coverage.limitations.push('URL lexical analysis cannot see page content or confirm intent.', 'Model scores are uncalibrated and can be wrong.');
    if (result.decisionSource === 'trusted-domain-override') {
      coverage.limitations.push('The trusted-domain list can be incomplete, and trust does not guarantee every page on the hostname is safe.');
    }
    if (result.decisionSource === 'outside-training-range') {
      coverage.limitations.push('The input was outside the model\'s observed training range, so the model output may be unreliable.');
    }
  } else if (inputType === 'email') {
    coverage.analyzed = ['Subject and body language', 'Embedded URLs (up to 10)', 'From/Reply-To domain comparison', 'Starter email text model', 'Presence of SPF/DKIM/DMARC header values'];
    coverage.notAnalyzed = ['Attachment contents', 'Full SMTP delivery path', 'SPF/DKIM/DMARC authentication results (header presence is not verification)', 'Sender identity'];
    coverage.limitations.push('The email text model is a starter baseline, not a validated production model.', 'Header presence does not prove authentication passed.', 'Encoded or opaque content may not expose URLs or intent.');
  } else if (inputType === 'qr') {
    const decodedIsUrl = typeof result.decodedData === 'string' && /^https?:\/\//i.test(result.decodedData);
    coverage.analyzed = ['QR code decoding'].concat(decodedIsUrl ? ['URL analysis of the decoded address'] : ['Decoded content inspection']);
    coverage.notAnalyzed = ['The QR image beyond the decoded payload', 'The safety of the decoded destination', 'Visual tampering in the QR image'];
    coverage.limitations.push('A QR code can point to a malicious site even if it looks ordinary.', 'Non-URL QR content cannot be checked automatically.');
  } else if (inputType === 'attachment') {
    coverage.analyzed = ['File extension', 'Visible file bytes for embedded URLs (up to 10)', 'ZIP content listing (for .zip files)', 'Macro markers', 'Suspicious account/security phrases'];
    coverage.notAnalyzed = ['File execution behavior (no sandbox)', 'Encrypted or encoded content', 'RAR/7z archive contents', 'Full document rendering', 'Whether embedded URLs are currently malicious beyond the URL scan'];
    coverage.limitations.push('This is not a malware sandbox verdict.', 'Only visible bytes are inspected; encoded or compressed content may hide threats.');
  } else if (inputType === 'screenshot') {
    coverage.analyzed = ['OCR text extraction', 'Phishing-style language indicators', 'URLs found in OCR text'];
    coverage.notAnalyzed = ['Visual brand verification', 'Whether the screenshot is genuine', 'The page behind the screenshot', 'Browser address-bar authenticity'];
    coverage.limitations.push('Screenshot analysis is an indicator, not proof of safety or maliciousness.', 'A screenshot can be edited or taken out of context.');
  } else if (inputType === 'domain') {
    coverage.level = 'informational';
    coverage.analyzed = ['DNS resolution', 'RDAP registration lookup', 'Optional VirusTotal lookup'];
    coverage.notAnalyzed = ['Phishing verdict (domain intelligence is informational)', 'Page content', 'Historical reputation'];
    coverage.limitations.push('Domain intelligence does not produce a phishing verdict.', 'Registration details may be privacy-redacted.');
  } else if (inputType === 'unavailable') {
    coverage.level = 'none';
    coverage.notAnalyzed = ['Everything'];
    coverage.limitations.push('The scan did not complete, so no evidence was produced.');
  }
  coverage.limitations = [...new Set(coverage.limitations.filter(Boolean))];
  return coverage;
}

function unknownsFor(result, inputType) {
  if (inputType === 'url') {
    return ['Whether the page content is safe', 'Whether the site is currently hosting malware or phishing', 'Whether external reputation services would flag it (not queried)'];
  }
  if (inputType === 'email') {
    return ['Whether the sender is who they claim to be', 'Whether SPF, DKIM, or DMARC authentication actually passed', 'Whether attachments are safe', 'Whether the message was delivered to other recipients'];
  }
  if (inputType === 'qr') {
    return ['Whether the decoded destination is safe', 'Whether the QR code was visually tampered with', 'Who created the QR code'];
  }
  if (inputType === 'attachment') {
    return ['Whether the file is malicious when opened', 'Whether encoded or encrypted content hides a threat', 'Whether the embedded links are currently malicious beyond the URL scan'];
  }
  if (inputType === 'screenshot') {
    return ['Whether the screenshot is genuine', 'Whether the page behind it is safe', 'Whether the brand shown is real'];
  }
  if (inputType === 'domain') {
    return ['Whether the domain is used for phishing', 'Whether the resolved IPs are shared with malicious sites', 'Registration details may be privacy-redacted'];
  }
  if (inputType === 'unavailable') return ['Everything about this item remains unconfirmed.'];
  return ['The input type could not be determined.'];
}

// Defence in depth for the optional hosted provider: even detector-authored
// finding text can contain a full URL, an email address, a hash, or a bare
// credential-like value. The local rule engine keeps the original text; only
// the hosted payload is reduced this way.
export function redactForHosted(value) {
  if (typeof value !== 'string') return value;
  return value
    .replace(/\bhttps?:\/\/[^\s<>"']+/gi, (match) => {
      try {
        return new URL(match).hostname;
      } catch {
        return '[redacted-url]';
      }
    })
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, '[redacted-email]')
    .replace(/\b[a-f0-9]{32,}\b/gi, '[redacted-hash]')
    .replace(/\b(token|password|passwd|pwd|secret|api[_-]?key|auth|session|otp)=([^\s&]+)/gi, '$1=[redacted]');
}

// Build the minimal, sanitised payload that may be sent to the optional hosted
// provider. Raw emails, attachment bytes, OCR text, full URLs, credentials, and
// hashes are intentionally excluded.
export function sanitizeEvidenceForHosted(evidence) {
  const source = evidence || {};
  const out = {
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
    inputType: safeText(source.inputType, 32) || 'unknown',
    verdict: safeText(source.verdict, 32) || 'unknown',
    decisionSource: safeText(source.decisionSource, 64) || 'unknown',
    model: source.model ? {
      role: safeText(source.model.role, 16),
      prediction: source.model.prediction ? safeText(source.model.prediction, 32) : null,
      score: safeNumber(source.model.score),
      calibrated: false,
      scoreMeaning: safeText(source.model.scoreMeaning, 240),
      components: Array.isArray(source.model.components)
        ? source.model.components.slice(0, 6).map((component) => ({
          name: safeText(component && component.name, 40),
          score: safeNumber(component && component.score),
        })).filter((component) => component.name)
        : [],
    } : null,
    ruleFindings: Array.isArray(source.ruleFindings)
      ? source.ruleFindings.slice(0, 20).map((finding) => safeText(redactForHosted(finding && finding.text), 240)).filter(Boolean)
      : [],
    observed: {},
    coverage: {
      level: safeText(source.coverage && source.coverage.level, 16) || 'unknown',
      analyzed: (source.coverage && Array.isArray(source.coverage.analyzed) ? source.coverage.analyzed : []).slice(0, 10).map((text) => safeText(text, 240)).filter(Boolean),
      notAnalyzed: (source.coverage && Array.isArray(source.coverage.notAnalyzed) ? source.coverage.notAnalyzed : []).slice(0, 10).map((text) => safeText(text, 240)).filter(Boolean),
      limitations: (source.coverage && Array.isArray(source.coverage.limitations) ? source.coverage.limitations : []).slice(0, 10).map((text) => safeText(text, 240)).filter(Boolean),
    },
    unknown: (Array.isArray(source.unknown) ? source.unknown : []).slice(0, 10).map((text) => safeText(text, 240)).filter(Boolean),
    disagreement: source.disagreement ? {
      modelPrediction: safeText(source.disagreement.modelPrediction, 32),
      verdict: safeText(source.disagreement.verdict, 32),
      overridden: !!source.disagreement.overridden,
    } : null,
    meta: {
      riskPercentage: safeNumber(source.meta && source.meta.riskPercentage),
      confidencePercentage: safeNumber(source.meta && source.meta.confidencePercentage),
      threatCategory: safeText(source.meta && source.meta.threatCategory, 80),
      scoreMeaning: safeText(source.meta && source.meta.scoreMeaning, 240),
    },
  };

  for (const key of HOSTED_OBSERVED_KEYS) {
    const value = source.observed ? source.observed[key] : undefined;
    if (value === null || value === undefined) continue;
    if (typeof value === 'string') {
      if (HOSTNAME_KEYS.has(key)) {
        const host = safeHostname(value);
        if (host) out.observed[key] = host;
      } else {
        const text = safeText(value, 253);
        if (text) out.observed[key] = text;
      }
    } else if (typeof value === 'number' && Number.isFinite(value)) {
      out.observed[key] = value;
    } else if (typeof value === 'boolean') {
      out.observed[key] = value;
    } else if (Array.isArray(value)) {
      const items = value.slice(0, 10).map((item) => safeText(item, 80)).filter(Boolean);
      if (items.length) out.observed[key] = items;
    }
  }
  return out;
}
