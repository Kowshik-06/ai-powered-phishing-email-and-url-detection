import React, { useEffect, useMemo, useState } from 'react';
import { buildEvidence } from '../explanations/evidence';
import { buildExplanation, DEFAULT_MODE, normalizeMode, SECTION_TITLES } from '../explanations/rules';
import RichText from '../explanations/RichText';
import {
  CONSENT_CATEGORIES,
  aiErrorMessage,
  fetchExplainConfig,
  requestHostedExplanation,
} from '../explanations/hosted';

const MODE_KEY = 'phishing.explanationMode';
const SECTION_IDS = ['whatWeFound', 'whyItMatters', 'whatToDoNext', 'whatWeCouldNotConfirm'];

function readStoredMode() {
  try {
    return normalizeMode(localStorage.getItem(MODE_KEY));
  } catch {
    return DEFAULT_MODE;
  }
}

function TechnicalDetails({ technical }) {
  const model = technical.model;
  return (
    <details className="mt-5 rounded-xl border border-slate-800 bg-slate-900/70 p-4" open>
      <summary className="cursor-pointer text-xs font-bold uppercase tracking-wide text-cyan-300">Technical evidence</summary>
      <dl className="mt-3 grid grid-cols-1 gap-3 text-xs sm:grid-cols-2">
        <div>
          <dt className="text-slate-500">Final verdict</dt>
          <dd className="font-bold text-slate-200">{technical.verdict}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Final risk</dt>
          <dd className="font-bold text-slate-200">{technical.riskPercentage === null ? 'Not available' : `${technical.riskPercentage}%`}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Decision source</dt>
          <dd className="text-slate-200">{technical.decisionSource || 'unknown'}</dd>
        </div>
        <div>
          <dt className="text-slate-500">Confidence</dt>
          <dd className="text-slate-200">
            {technical.confidencePercentage === null ? 'Not available' : `${technical.confidencePercentage}%`}
            <span className="block text-slate-500">{technical.confidenceMeaning}</span>
          </dd>
        </div>
        <div className="sm:col-span-2">
          <dt className="text-slate-500">Underlying model</dt>
          <dd className="text-slate-200">
            {model
              ? `${model.prediction || 'no label'} · raw score ${model.score === null ? 'not available' : `${model.score}%`} · calibrated: no`
              : 'No model score is available for this input type.'}
          </dd>
        </div>
        {model && model.scoreMeaning && (
          <div className="sm:col-span-2">
            <dt className="text-slate-500">Score meaning</dt>
            <dd className="text-slate-200">{model.scoreMeaning}</dd>
          </div>
        )}
        {technical.disagreement && (
          <div className="sm:col-span-2">
            <dt className="text-slate-500">Model vs verdict</dt>
            <dd className="text-amber-300">Model: {technical.disagreement.modelPrediction} · Final: {technical.disagreement.verdict}</dd>
          </div>
        )}
      </dl>

      {model && model.components && model.components.length > 0 && (
        <div className="mt-4">
          <h5 className="text-xs font-bold text-slate-400">Model components</h5>
          <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-3">
            {model.components.map((component) => (
              <div key={component.name} className="rounded bg-slate-950 p-2 text-xs">
                <div className="text-slate-500">{component.name}</div>
                <div className="font-bold text-cyan-300">{component.score}%</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="mt-4">
        <h5 className="text-xs font-bold text-slate-400">Rule findings</h5>
        {technical.ruleFindings.length > 0 ? (
          <ul className="mt-2 space-y-1">
            {technical.ruleFindings.map((text, index) => (
              <li key={index} className="text-xs text-slate-300">• {text}</li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-xs text-slate-500">No individual rule findings were returned.</p>
        )}
      </div>

      <div className="mt-4">
        <h5 className="text-xs font-bold text-slate-400">Observed values</h5>
        <pre className="mt-2 overflow-auto rounded bg-slate-950 p-3 text-xs text-slate-300">{JSON.stringify(technical.observed, null, 2)}</pre>
      </div>

      <div className="mt-4">
        <h5 className="text-xs font-bold text-slate-400">Coverage</h5>
        <p className="mt-1 text-xs text-slate-400">Analyzed: {technical.coverage.analyzed && technical.coverage.analyzed.length ? technical.coverage.analyzed.join('; ') : 'not available'}</p>
        <p className="mt-1 text-xs text-slate-400">Not analyzed: {technical.coverage.notAnalyzed && technical.coverage.notAnalyzed.length ? technical.coverage.notAnalyzed.join('; ') : 'not available'}</p>
      </div>

      <div className="mt-4">
        <h5 className="text-xs font-bold text-slate-400">Unknown</h5>
        {technical.unknown.length > 0 ? (
          <ul className="mt-2 space-y-1">
            {technical.unknown.map((text, index) => (
              <li key={index} className="text-xs text-slate-300">• {text}</li>
            ))}
          </ul>
        ) : (
          <p className="mt-2 text-xs text-slate-500">No additional unknowns were listed.</p>
        )}
      </div>
    </details>
  );
}

function HostedControls({ config, consent, setConsent, state, onSend }) {
  if (config.status !== 'ready') return null;
  if (!config.enabled) {
    return (
      <p className="mt-5 border-t border-slate-800 pt-4 text-xs text-slate-500">
        Hosted AI explanation is unavailable or not configured on this server. The explanation above is generated locally and works without an API key or internet connection.
      </p>
    );
  }
  return (
    <div className="mt-5 border-t border-slate-800 pt-4">
      <h4 className="text-xs font-bold uppercase tracking-wide text-slate-400">Optional hosted AI explanation</h4>
      <p className="mt-2 text-xs text-slate-400">
        A hosted AI can explain the verified findings below in a more conversational way. It cannot change the verdict or risk score. Nothing is sent until you consent.
      </p>
      <p className="mt-2 text-xs text-slate-400">
        <strong className="text-slate-300">What would be sent:</strong> {CONSENT_CATEGORIES.join(', ')}. Raw email bodies, attachment contents, screenshot text, full URLs, and credentials are never sent.
      </p>
      {state.status === 'idle' && (
        <div className="mt-3">
          <label className="flex items-start gap-2 text-xs text-slate-300">
            <input
              type="checkbox"
              checked={consent}
              onChange={(event) => setConsent(event.target.checked)}
              className="mt-0.5"
            />
            <span>I understand and consent to sending this sanitized evidence to the hosted provider.</span>
          </label>
          <button
            type="button"
            onClick={onSend}
            disabled={!consent}
            className="mt-3 rounded-lg bg-cyan-500 px-4 py-2 text-xs font-bold text-slate-950 disabled:opacity-40"
          >
            Get AI explanation
          </button>
        </div>
      )}
      {state.status === 'loading' && <p className="mt-3 text-xs text-cyan-300" role="status">Requesting a hosted explanation…</p>}
      {state.status === 'error' && (
        <p className="mt-3 text-xs text-amber-300" role="status">
          Hosted explanation unavailable ({aiErrorMessage(state.error)}). The local rule-based explanation above is still valid.
        </p>
      )}
      {state.status === 'done' && state.sections && (
        <div className="mt-3 space-y-3">
          <p className="text-xs text-slate-500">AI-generated from the verified findings. It cannot change the verdict or score.</p>
          {SECTION_IDS.map((key) => (
            typeof state.sections[key] === 'string' && state.sections[key].trim() ? (
              <div key={key}>
                <div className="text-xs font-bold uppercase tracking-wide text-slate-400">{SECTION_TITLES.en[key]}</div>
                <p className="mt-1 text-sm leading-relaxed text-slate-300"><RichText text={state.sections[key]} /></p>
              </div>
            ) : null
          ))}
        </div>
      )}
    </div>
  );
}

export default function ExplanationPanel({ result, inputType }) {
  const [mode, setMode] = useState(readStoredMode);
  const [config, setConfig] = useState({ status: 'loading', enabled: false });
  const [consent, setConsent] = useState(false);
  const [hostedState, setHostedState] = useState({ status: 'idle', sections: null, error: null });

  const evidence = useMemo(() => buildEvidence(result, { inputType }), [result, inputType]);
  const explanation = useMemo(() => buildExplanation(evidence, mode), [evidence, mode]);

  useEffect(() => {
    let cancelled = false;
    setConfig({ status: 'loading', enabled: false });
    fetchExplainConfig()
      .then((value) => {
        if (!cancelled) setConfig({ status: 'ready', enabled: !!(value && value.enabled), model: value && value.model });
      })
      .catch(() => {
        if (!cancelled) setConfig({ status: 'ready', enabled: false });
      });
    return () => { cancelled = true; };
  }, []);

  useEffect(() => {
    setConsent(false);
    setHostedState({ status: 'idle', sections: null, error: null });
  }, [result, inputType]);

  const changeMode = (next) => {
    const normalized = normalizeMode(next);
    setMode(normalized);
    try { localStorage.setItem(MODE_KEY, normalized); } catch { /* storage is optional */ }
  };

  const send = async () => {
    if (consent !== true || hostedState.status === 'loading') return;
    setHostedState({ status: 'loading', sections: null, error: null });
    try {
      const data = await requestHostedExplanation({ evidence, consent: true });
      setHostedState({ status: 'done', sections: data.sections, error: null });
    } catch (error) {
      setHostedState({ status: 'error', sections: null, error: (error && error.code) || 'provider_unavailable' });
    }
  };

  return (
    <section className="mt-6 rounded-2xl border border-slate-700/60 bg-slate-950/40 p-5" aria-label="Explanation">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h3 className="text-sm font-bold text-cyan-400">EXPLANATION</h3>
        <div role="group" aria-label="Explanation mode" className="inline-flex overflow-hidden rounded-lg border border-slate-700">
          {['beginner', 'expert'].map((value) => (
            <button
              key={value}
              type="button"
              aria-pressed={mode === value}
              onClick={() => changeMode(value)}
              className={`px-3 py-1.5 text-xs font-bold ${mode === value ? 'bg-cyan-500 text-slate-950' : 'bg-slate-900 text-slate-400 hover:text-slate-200'}`}
            >
              {value === 'beginner' ? 'Beginner' : 'Expert'}
            </button>
          ))}
        </div>
      </div>

      <p className="mt-3 text-xs text-slate-500">
        Same scan result in both modes. Verdict:{' '}
        <span className="font-bold text-slate-300">{explanation.verdictLabel}</span>
        {explanation.riskPercentage !== null && (
          <> · Final risk: <span className="font-bold text-slate-300">{explanation.riskPercentage}%</span></>
        )}
      </p>
      <p className="mt-1 text-sm font-bold text-slate-100">{explanation.headline}</p>

      <div className="mt-4 grid gap-4 md:grid-cols-2">
        {explanation.sections.map((section) => (
          <section key={section.id} aria-labelledby={`explanation-${section.id}`}>
            <h4 id={`explanation-${section.id}`} className="text-xs font-bold uppercase tracking-wide text-slate-400">{section.title}</h4>
            <ul className="mt-2 space-y-2">
              {section.items.map((item, index) => (
                <li key={index} className="text-sm leading-relaxed text-slate-300"><RichText text={item} /></li>
              ))}
            </ul>
          </section>
        ))}
      </div>

      {mode === 'expert' && explanation.technical && <TechnicalDetails technical={explanation.technical} />}

      <HostedControls
        config={config}
        consent={consent}
        setConsent={setConsent}
        state={hostedState}
        onSend={send}
      />
    </section>
  );
}
