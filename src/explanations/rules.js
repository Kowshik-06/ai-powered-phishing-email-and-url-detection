// Deterministic, offline explanation engine.
//
// The engine only reads the evidence object. It never changes the verdict or
// risk score, never invents findings, and never calls a network service.

import { safeNumber, safeText } from './evidence';

export const DEFAULT_MODE = 'beginner';

export const SECTION_TITLES = {
  en: {
    whatWeFound: 'What we found',
    whyItMatters: 'Why it matters',
    whatToDoNext: 'What to do next',
    whatWeCouldNotConfirm: 'What we could not confirm',
  },
};

export function normalizeMode(mode) {
  return mode === 'expert' ? 'expert' : 'beginner';
}

export function verdictLabel(value) {
  switch (value) {
    case 'phishing': return 'Phishing';
    case 'legitimate': return 'Likely legitimate';
    case 'suspicious': return 'Suspicious';
    case 'review': return 'Needs review';
    case 'unavailable': return 'Analysis unavailable';
    default: return 'Unknown';
  }
}

function isNoSignalText(text) {
  return /^no strong phishing indicators|^no embedded urls|^no readable text|^no readable qr|^no high-risk attachment/i.test(String(text || '').trim());
}

function decisionSourceText(source) {
  switch (source) {
    case 'trusted-domain-override': return 'the trusted-domain rule overrides the model for recognized hostnames';
    case 'outside-training-range': return 'the input was outside the model\'s observed training range and was marked for review';
    case 'hybrid-rules': return 'the email risk combines rule indicators, the email text model, and embedded URL analysis';
    case 'rules-and-embedded-url': return 'the attachment risk combines file rules with the URL detector for embedded links';
    case 'rules-and-ocr-url': return 'the screenshot risk combines text indicators with the URL detector for links found in the image';
    case 'model': return 'the trained model produced the final decision';
    case 'informational': return 'domain intelligence is informational and does not produce a verdict';
    case 'unavailable': return 'the scan did not complete';
    default: return 'the detector applied its final decision logic';
  }
}

function headlineFor(verdict, trusted) {
  if (verdict === 'phishing') return 'Strong phishing signals were found';
  if (verdict === 'legitimate') return trusted ? 'This hostname is on the trusted-domain list' : 'No strong phishing signals were found';
  if (verdict === 'suspicious') return 'Some signals look suspicious';
  if (verdict === 'review') return 'This item needs a manual review';
  if (verdict === 'unavailable' || verdict === 'unknown') return 'The scan could not be completed';
  return 'The result could not be interpreted';
}

export function buildExplanation(evidence, mode = DEFAULT_MODE, options = {}) {
  const ev = evidence || {};
  const locale = options.locale === 'en' ? 'en' : 'en';
  const normalizedMode = normalizeMode(mode);
  const verdict = ev.verdict || 'unknown';
  const risk = safeNumber(ev.meta && ev.meta.riskPercentage);
  const trusted = ev.decisionSource === 'trusted-domain-override';
  const rangeReview = ev.decisionSource === 'outside-training-range';
  const hostname = ev.observed && ev.observed.hostname;
  const model = ev.model || null;
  const findings = (ev.ruleFindings || []).filter((finding) => finding && typeof finding.text === 'string');
  const signalFindings = findings.filter((finding) => !isNoSignalText(finding.text));
  const noSignalFinding = findings.find((finding) => isNoSignalText(finding.text));

  const content = { whatWeFound: [], whyItMatters: [], whatToDoNext: [], whatWeCouldNotConfirm: [] };
  const add = (section, text, max = 700) => {
    const clean = safeText(text, max);
    if (clean && !content[section].includes(clean)) content[section].push(clean);
  };

  // --- What we found -------------------------------------------------------
  if (verdict === 'unavailable' || verdict === 'unknown') {
    add('whatWeFound', 'The scan did not produce a usable verdict, so there is no risk score to report.');
  } else {
    add('whatWeFound', `The scanner's final verdict is ${verdictLabel(verdict).toLowerCase()}${risk !== null ? ` with a final risk score of ${risk}%` : ''}.`);
  }

  if (hostname) add('whatWeFound', `The checked hostname is ${hostname}.`);

  if (trusted) {
    add('whatWeFound', 'The hostname matched the built-in trusted-domain list, so the trusted-domain rule set the final verdict to legitimate.');
    if (model && model.prediction) {
      add('whatWeFound', `The underlying model's raw output was ${model.prediction}${model.score !== null ? ` at a raw score of ${model.score}%` : ''}. That model output is kept separate from the final verdict.`);
    }
  }

  if (rangeReview || verdict === 'review') {
    const rangeFinding = findings.find((finding) => /outside the observed training range|outside training range/i.test(finding.text));
    if (rangeFinding) add('whatWeFound', rangeFinding.text);
    else if (verdict === 'review') add('whatWeFound', 'The scanner marked this item for manual review instead of making a confident automatic decision.');
  }

  if (signalFindings.length) {
    const limit = normalizedMode === 'beginner' ? 4 : 20;
    signalFindings.slice(0, limit).forEach((finding) => add('whatWeFound', finding.text));
    if (signalFindings.length > limit) {
      add('whatWeFound', `The detector reported ${signalFindings.length - limit} more signal(s). Switch to Expert mode to see them all.`);
    }
  } else if (verdict === 'phishing' || verdict === 'suspicious') {
    add('whatWeFound', 'The detector did not return individual reason text for this result, but its final verdict is based on the model and rule output.');
  } else if (verdict === 'legitimate') {
    add('whatWeFound', noSignalFinding ? noSignalFinding.text : 'The detector did not report any strong phishing signals.');
  }

  if (model && model.score !== null && !trusted) {
    if (normalizedMode === 'expert') {
      add('whatWeFound', `Underlying model${model.prediction ? ` prediction: ${model.prediction}` : ''}; raw score ${model.score}%; calibrated: no. ${model.scoreMeaning || ''}`);
      if (model.role === 'component') add('whatWeFound', 'This model score is one component of the email risk, not the final risk score.');
    } else {
      add('whatWeFound', `The trained model's raw score was ${model.score}%. It is not a calibrated probability.`);
    }
  }

  if (ev.disagreement) {
    add('whatWeFound', `The model's raw prediction was ${ev.disagreement.modelPrediction}, but the final verdict is ${verdictLabel(verdict).toLowerCase()} because ${decisionSourceText(ev.decisionSource)}.`);
  }

  // --- Why it matters ------------------------------------------------------
  if (verdict === 'phishing') {
    add('whyItMatters', 'Phishing items are designed to steal passwords, payment details, or personal information. Acting on this one could put your accounts or money at risk.');
  } else if (verdict === 'legitimate') {
    if (trusted) {
      add('whyItMatters', 'The trusted-domain rule is a shortcut, not a safety guarantee. A trusted hostname can still host user content, redirects, or compromised pages.');
    } else {
      add('whyItMatters', 'A legitimate result means the checked signals look normal. It does not prove the item is safe: sites can be compromised, and new phishing pages can appear at any time.');
    }
  } else if (verdict === 'suspicious') {
    add('whyItMatters', 'Some signals look risky, but the evidence is not strong enough for a confident phishing verdict. Treat it cautiously.');
  } else if (verdict === 'review') {
    add('whyItMatters', 'The scanner could not make a reliable automatic decision. Ignoring a review result could expose you to an unchecked risk.');
  } else {
    add('whyItMatters', 'Without a completed analysis, there is no evidence to support a safe or unsafe conclusion.');
  }

  // --- What to do next -----------------------------------------------------
  if (verdict === 'phishing' || verdict === 'suspicious') {
    add('whatToDoNext', 'Do not open the link, download the file, or enter credentials.');
    add('whatToDoNext', 'If it claims to be a service you use, open that service\'s official app or type its address yourself.');
    add('whatToDoNext', 'Report or delete the message.');
  } else if (verdict === 'legitimate') {
    add('whatToDoNext', 'Before signing in, check the hostname spelling and make sure you reached the site through an address you trust.');
    add('whatToDoNext', 'Avoid entering sensitive data through unexpected links, even when the signal looks normal.');
  } else if (verdict === 'review') {
    add('whatToDoNext', 'Treat the item as untrusted until a person or trusted source confirms it.');
    add('whatToDoNext', 'Do not enter credentials or make payments based on this item.');
  } else {
    add('whatToDoNext', 'Try the scan again.');
    add('whatToDoNext', 'If it still fails, inspect the item through another trusted tool.');
    add('whatToDoNext', 'Do not treat the failure as a safe result.');
  }
  if (trusted) add('whatToDoNext', 'Confirm the address is the real trusted domain and not a look-alike.');
  if (ev.inputType === 'email') add('whatToDoNext', 'If the message contains an attachment, do not open it unless you expected it and trust the sender.');
  if (ev.inputType === 'attachment') add('whatToDoNext', 'Do not open the file unless you expected it and trust the sender.');
  if (ev.inputType === 'qr') add('whatToDoNext', 'If you did not expect the QR code, do not open the decoded address.');
  if (ev.inputType === 'screenshot') add('whatToDoNext', 'Verify the destination independently; a screenshot can be edited or taken out of context.');

  // --- What we could not confirm ------------------------------------------
  const limitations = (ev.coverage && ev.coverage.limitations) || [];
  const notAnalyzed = (ev.coverage && ev.coverage.notAnalyzed) || [];
  const unknown = ev.unknown || [];
  if (normalizedMode === 'beginner') {
    [...limitations, ...unknown].slice(0, 4).forEach((text) => add('whatWeCouldNotConfirm', text));
  } else {
    limitations.forEach((text) => add('whatWeCouldNotConfirm', text));
    notAnalyzed.forEach((text) => add('whatWeCouldNotConfirm', `Not analyzed: ${text}`));
    unknown.forEach((text) => add('whatWeCouldNotConfirm', `Unknown: ${text}`));
  }
  if (verdict === 'legitimate') add('whatWeCouldNotConfirm', 'We could not confirm who operates the site, whether it has been compromised, or whether the page content is safe.');
  if (verdict === 'phishing') add('whatWeCouldNotConfirm', 'We did not open the page or verify its live reputation. The exact content and current status are unknown.');
  if (verdict === 'review') add('whatWeCouldNotConfirm', 'We could not confirm whether this item is safe or malicious.');
  if (verdict === 'unavailable' || verdict === 'unknown') add('whatWeCouldNotConfirm', 'Everything about this item remains unconfirmed.');
  add('whatWeCouldNotConfirm', 'This is an automated assessment, not a guarantee.');

  // --- Expert-only technical view -----------------------------------------
  const technical = normalizedMode === 'expert' ? {
    verdict: ev.verdict || 'unknown',
    riskPercentage: risk,
    confidencePercentage: safeNumber(ev.meta && ev.meta.confidencePercentage),
    confidenceMeaning: 'Distance from the 50% model decision boundary. It is not a calibrated probability that the verdict is correct.',
    decisionSource: ev.decisionSource,
    model: model ? {
      role: model.role,
      prediction: model.prediction,
      score: model.score,
      calibrated: false,
      scoreMeaning: model.scoreMeaning,
      components: model.components || [],
    } : null,
    ruleFindings: findings.map((finding) => finding.text),
    observed: ev.observed || {},
    coverage: ev.coverage || {},
    disagreement: ev.disagreement || null,
    unknown: ev.unknown || [],
    limitations,
  } : null;

  const titles = SECTION_TITLES[locale];
  return {
    schemaVersion: 1,
    locale,
    mode: normalizedMode,
    verdict: ev.verdict || 'unknown',
    verdictLabel: verdictLabel(verdict),
    riskPercentage: risk,
    headline: headlineFor(verdict, trusted),
    sections: [
      { id: 'whatWeFound', title: titles.whatWeFound, items: content.whatWeFound },
      { id: 'whyItMatters', title: titles.whyItMatters, items: content.whyItMatters },
      { id: 'whatToDoNext', title: titles.whatToDoNext, items: content.whatToDoNext },
      { id: 'whatWeCouldNotConfirm', title: titles.whatWeCouldNotConfirm, items: content.whatWeCouldNotConfirm },
    ],
    technical,
    source: 'rules',
  };
}
