# AI-Powered Phishing Email and URL Detection

A local web application for analyzing suspicious URLs, email text, uploaded files, and QR codes. It combines trained URL classifiers with rule-based indicators and presents risk scores and explanations to support review. This is an educational demonstration, not a guarantee that a message or destination is safe.

## Problem Statement

Phishing messages often use look-alike domains, urgency, and account-verification language to persuade recipients to disclose credentials or payment information. This project demonstrates how URL models and email/file indicators can be combined into an explainable local screening workflow.

## Main Features

- URL classification with model scores, risk, confidence, threat category, and lexical reasons.
- Email analysis of subject/body, embedded URLs, and From/Reply-To mismatch signals.
- File analysis for embedded URLs, executable/script extensions, Office macro markers, and ZIP contents.
- QR-code decoding; decoded URLs are sent through the existing URL detector.
- Dashboard with scan history, model metrics, analytics, and an admin overview.
- Optional domain intelligence using DNS and RDAP, with VirusTotal support when configured.
- Screenshot visual inspection and PDF report generation.
- Beginner/Expert explanations with a curated glossary, plus an optional consent-gated hosted AI summary.

## System Architecture

1. The React frontend reads user input and sends authenticated requests to the Express backend.
2. The backend handles authentication, local scan history, and API requests on port `5000`.
3. The Python ML service exposes prediction and analysis endpoints on `127.0.0.1:5100`.
4. URL predictions use the trained models; email, file, and QR analysis reuse URL predictions when links are present.

## Technology Stack

- Frontend: React 18, Create React App, Axios, Tailwind CSS, Recharts, and Lucide icons.
- Backend: Node.js, Express, and `cors`.
- ML service: Python, scikit-learn, PyTorch, pandas, NumPy, joblib, and OpenCV.
- Supporting features: ReportLab PDF generation; optional DNS, RDAP, and VirusTotal lookups.

## ML Models and Evaluation

The supplied evaluation artifacts report these hold-out results:

| Model | Accuracy |
|---|---:|
| Random Forest | 90.2% |
| HistGradientBoosting | 91.2% |
| Deep Learning (PyTorch MLP) | 88.5% |

HistGradientBoosting ROC-AUC: **96.8%**.

These results come from a random stratified split of the engineered-feature dataset. It contains 2,488 rows and 1,134 duplicate rows, so the scores may overstate generalization to new domains. They are evaluation results, not a real-world accuracy guarantee. The dataset is not included until its source and redistribution terms are documented. The trained URL model artifacts are required for inference; see [Model Artifacts](#model-artifacts) for the expected files and configuration.

A reproducible duplicate-aware diagnostic was also run on this feature-only file: identical 13-feature rows were kept together, 41 conflicting-label groups (229 rows) were excluded, and the remaining 1,272 unique unambiguous vectors were split 80/20 with seed 42 (1,017 train, 255 test). This re-fit equivalent estimators in memory only; it did not overwrite or evaluate the saved production artifacts. Rows were not grouped by domain because no domain column exists. The original random row split had an identical feature vector in train for 269/498 test rows (54.02%).

| In-memory estimator | Accuracy | Precision | Recall | F1 | ROC-AUC | FPR | FNR | Confusion matrix (TN,FP;FN,TP) |
|---|---:|---:|---:|---:|---:|---:|---:|---|
| Random Forest | 83.92% | 82.54% | 63.41% | 71.72% | 90.48% | 6.36% | 36.59% | `[[162,11],[30,52]]` |
| HistGradientBoosting | 82.75% | 79.69% | 62.20% | 69.86% | 86.08% | 7.51% | 37.80% | `[[160,13],[31,51]]` |
| Deep Learning | 82.35% | 81.36% | 58.54% | 68.09% | 84.12% | 6.36% | 41.46% | `[[162,11],[34,48]]` |
| Weighted ensemble (80/10/10) | 82.35% | 79.37% | 60.98% | 68.97% | 87.16% | 7.51% | 39.02% | `[[160,13],[32,50]]` |

These are results on engineered feature vectors, not raw URLs or independent domains. They cannot establish performance on current benign/phishing URLs, nor rule out overlap between this undocumented dataset and saved model training data.

## Research Dataset Audit and Reproducible Evaluation

The audited dataset (not included in this snapshot) has 2,488 rows, 13 numeric engineered features, and `target`; it has **no raw URL, hostname/domain, timestamp, collection-source, or row-level provenance columns**. The training scripts consume those precomputed columns directly, so this file cannot verify the original URL feature semantics or be reprocessed through `url_features.py`. The training scripts use row-wise stratified 80/20 splits with seed 42. A prior audit found 1,134 exact duplicate rows, 41 feature vectors with conflicting labels (229 rows), and 269 of 498 test rows with a feature vector also present in train. Those stored random-split metrics may therefore overstate generalization. Current file source and redistribution permission have not been established; it remains ignored by Git.

The separate `ml-service/evaluate_raw_urls.py` accepts a user-approved CSV and only reads it. It does not download data, visit URLs, train models, or write model artifacts. It requires explicit source/version/license metadata and explicit label mapping, removes normalized exact duplicates, excludes all conflicting-label groups, and uses a fixed-seed `GroupShuffleSplit` (by a supplied domain column when available, otherwise by parsed hostname; normalized URL grouping is also available). It extracts the existing 13 production features and evaluates the saved RF, HGB, deep-learning model, and 80/10/10 weighted ensemble at score threshold 0.5. Reports include accuracy, precision, recall, F1, ROC-AUC where both classes exist, FPR, FNR, confusion matrices, dataset hash, artifact hashes/configuration, split counts, and class counts. It does not include trusted-domain overrides or the separate REVIEW decision in binary classifier metrics. Production training-data overlap for external datasets remains unknown until provenance is recorded.

### Public Dataset Candidates (Not Downloaded)

| Source | Verified details | Research caveats |
|---|---|---|
| [UCI PhiUSIIL Phishing URL (Website)](https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset) | 235,795 rows; 134,850 legitimate and 100,945 phishing; includes `URL`, `Domain`, and label plus 54 fields; UCI page states CC BY 4.0. Donated March 2024. | Landing page describes the collection as mostly latest URLs and points to the 2024 paper; no per-row timestamps are listed in its field inventory. Its labels are reversed from this project: `1` legitimate, `0` phishing. Page-derived features must not be used as inputs to this URL-only model. Re-check the paper, archive snapshot, and license attribution before publication. |
| [ISCX-URL-2016](https://www.unb.ca/cic/datasets/url-2016.html) | UNB documents raw URL groups including over 35,300 benign URLs and around 10,000 phishing URLs, the latter sourced from OpenPhish; additional malware, spam, and defacement classes are described. | Old collection (2016); benign examples came from Alexa and were VirusTotal-filtered. Download page does not state a clear reuse license, so obtain/check permission before redistributing or publishing derived data. Class definitions/source methods differ from a current phishing-only benchmark. |
| [PhishTank developer feed](https://phishtank.org/developer_info.php) | Verified, online phishing feed; CSV/JSON includes raw URL, submission time, verification time, online flag, and target. Feed is updated hourly; application key is required for sustained downloads. | Live feed is not a frozen benchmark. Snapshot and cite retrieval time; retain only permitted fields and follow Cisco terms/EULA. It supplies phishing positives, not a matched benign class. |
| [Tranco ranking](https://tranco-list.eu/) | Research-oriented, versioned popular-domain list; standard list aggregates four rankings over 30 days and has permanent list IDs. | Popularity is not proof of benignness and a domain list is not a labeled raw-URL dataset. Source attribution/licensing varies among upstream rankings; do not automatically treat every listed URL as safe. Use only as a candidate source with independent filtering and clearly stated bias. |
| [UCI Phishing Websites](https://archive.ics.uci.edu/dataset/327/phishing+websites) | 11,055 rows, 30 fields; CC BY 4.0; UCI describes historical collection sources including PhishTank and search operators. | Feature-only data, no raw URL column; not usable to reproduce this project's extractor. Donated 2015. |

URLhaus is deliberately not recommended as a phishing label source: its official policy says it collects URLs directly distributing malware and explicitly excludes phishing. No external dataset was downloaded during this work.

### Import and Run

After reviewing the chosen dataset's paper, terms, and labels, manually place the approved CSV under the ignored `ml-service/datasets/` directory. Do not open or browse the URLs. Verify the source CSV column headers, freeze its version/snapshot, and map labels explicitly. For the UCI PhiUSIIL convention (benign `1`, phishing `0`) and its `URL`/`Domain` fields, the command is:

```powershell
Set-Location .\ml-service
.\.venv\Scripts\python.exe .\evaluate_raw_urls.py `
	--csv .\datasets\approved_raw_urls.csv `
	--dataset-name "UCI PhiUSIIL Phishing URL (Website)" `
	--source-url "https://archive.ics.uci.edu/dataset/967/phiusiil+phishing+url+dataset" `
	--dataset-version "record the downloaded archive date/hash" `
	--dataset-license "CC BY 4.0; verify attribution/terms" `
	--url-column URL --label-column label --domain-column Domain `
	--benign-label 1 --phishing-label 0 --group-by domain `
	--test-size 0.2 --seed 42 `
	--output .\datasets\approved_raw_urls-evaluation.json
```

The output path is created exclusively; an existing file is never overwritten. For a dataset without a usable domain field, omit `--domain-column` and choose `--group-by url`; this does not establish domain-independent generalization. Group splitting can also yield class imbalance; the report records test class counts and returns ROC-AUC as unavailable if a test fold contains one class. Raw URL content and per-row predictions are not emitted in the report.

## URL Detection

The URL feature extractor calculates lexical and structural features such as URL length, HTTPS, punctuation, hyphens, and selected security-related terms. The ensemble risk is weighted as:

`80% HistGradientBoosting + 10% Random Forest + 10% Deep Learning`

Confidence is derived from distance from a 50% ensemble score; uncertain/disagreeing results can be labeled suspicious. A small built-in list of recognized high-profile domains receives a low-risk safety override. Allowlists can be incomplete and must not be treated as proof of safety.

## Email and File Detection

Email analysis parses raw email content, scores urgency and credential-related language, checks for a From/Reply-To domain mismatch, and analyzes up to ten extracted URLs. It also returns available SPF, DKIM, and DMARC-related header information. The bundled email text model is a starter baseline trained on built-in examples, not a substitute for evaluation on a licensed representative dataset.

File analysis accepts uploaded files as bytes. It extracts up to ten visible HTTP(S) URLs and sends each to the same URL detector used by direct URL scans. File risk is raised to the highest embedded URL risk; additional indicators cover executable/script extensions, macro markers, and executable content in ZIP archives. Text such as `.txt` and raw `.eml` content can be analyzed, but encoded or opaque document content may not expose URLs to this byte-level scan. This is not a malware sandbox verdict.

## QR Detection

OpenCV decodes QR codes from uploaded images. If decoded content is a URL, the URL detector classifies it. Non-URL QR content is marked for review. An unreadable QR image is reported as such.

## Risk, Confidence, and Explanations

- URL risk is the weighted model ensemble score, except for the explicit trusted-domain override.
- URL confidence is derived from distance from 50%; it is not a calibrated probability of correctness.
- Email risk combines rule indicators and the starter email-text model, adds a From/Reply-To mismatch signal when applicable, and incorporates embedded URL risk.
- Admin monitoring for users, system-wide scan history, and persisted critical alerts.
- File risk starts at a low baseline, adds attachment-type/content indicators, and is raised by suspicious embedded URL risk.
- Results include human-readable indicators such as missing HTTPS, phishing-style account/security language, and suspicious embedded URLs. Reasons describe detected signals; they do not prove intent.

## Explanation System (Beginner and Expert)

The result panel includes a hybrid explanation system. It always starts with the deterministic rule-based explanation, which runs from the scan result without an API key or internet connection. A hosted AI explanation is optional, disabled by default, and only used after explicit per-request consent.

### How the evidence is built

`src/explanations/evidence.js` normalises the detector's existing response into a shared, read-only evidence object. It separates:

- observed facts (for example the parsed hostname, HTTPS flag, counts, domains, or file extension);
- underlying model output (prediction, raw score, calibration status, model components);
- rule findings and the decision source;
- coverage (what was analyzed, what was not, and known limitations);
- unknowns (what the scan could not confirm).

Missing values stay missing. They are listed as unknown and are never rewritten as a negative finding. For example, an absent HTTPS field does not produce "no HTTPS". A failed scan is recorded as unavailable with coverage level `none`; it does not inherit the coverage labels of the input type it was trying to analyze.

Evidence coverage by input type:

- **URL:** lexical/structural features, the trained URL model, and the trusted-domain rule. Page content and live reputation are not checked.
- **Email:** subject/body language, up to ten embedded URLs, From/Reply-To domains, the starter email text model, and header presence. Attachments, the SMTP path, and actual SPF/DKIM/DMARC authentication are not checked.
- **QR:** the decoded payload; URL payloads reuse the URL detector. The image beyond the payload and visual tampering are not checked.
- **Attachment:** extension, visible bytes, embedded URLs, ZIP listing, macro markers, and text phrases. The file is not executed and encrypted or encoded content may hide threats.
- **Screenshot:** OCR text, language indicators, and URLs found in the text. Brand authenticity and the page behind the screenshot are not verified.
- **Domain:** DNS, RDAP, and optional VirusTotal results. Domain intelligence is informational and does not produce a phishing verdict.

### Deterministic rule engine

`src/explanations/rules.js` builds four ordered sections: **What we found**, **Why it matters**, **What to do next**, and **What we could not confirm**. It has templates for phishing, legitimate, suspicious, review/outside-training-range, trusted-domain override, model/verdict disagreement, and unavailable analysis. It never calls a network service, never changes the verdict or risk score, and never describes an uncalibrated score as a probability. A legitimate verdict is presented as "no strong signals found", not as proof of safety.

### Modes and tooltips

Both modes use the same underlying scan result. Switching modes only changes the amount of detail; it cannot change the verdict or score. The default is Beginner. The preference is stored in `localStorage` under `phishing.explanationMode`; no scanned content is stored. Expert mode adds a technical block with the decision source, raw model score and calibration status, model components, rule findings, observed values, coverage, and unknowns.

Technical terms are annotated with a curated glossary (`src/explanations/glossary.js`). Tooltips open on hover or keyboard focus, toggle on tap, and close with Escape, a second tap, or an outside click. Only terms with a verified definition are annotated; everything else is rendered as plain text.

### Optional hosted AI explanation

The hosted adapter (`backend/explain.js`) is a generic OpenAI-compatible chat-completions client built on Node's built-in `fetch`. It adds no dependency and is disabled unless the operator configures it.

Privacy safeguards:

- The frontend sends only the sanitised evidence object; the backend re-sanitises and allowlists it again.
- Raw email bodies, attachment contents, screenshot text, full URLs, credentials, and hashes are never sent. URL evidence is reduced to the parsed hostname; email evidence is reduced to domains and counts.
- Detector finding text is reduced again before sending: a full URL becomes its hostname, email addresses become `[redacted-email]`, 32+ character hex hashes become `[redacted-hash]`, and credential-like `key=value` pairs become `key=[redacted]`. The local explanation keeps the original finding text.
- The API key exists only in the backend process environment. `/explain/config` returns safe metadata (enabled, model, limits) and never the key or upstream URL.
- Each request must include `consent: true`. Without it, the endpoint returns `400` and does not contact the provider.
- The provider must be an `https://` endpoint. Plain `http://` is accepted only for `127.0.0.1` or `localhost` local model servers.
- Requests have a timeout (default 12,000 ms), the response is size-limited, and the returned JSON must contain the four expected non-empty string sections. Malformed output is rejected; oversized sections are truncated to the configured budget.
- Provider errors are mapped to stable codes (`provider_timeout`, `provider_rate_limited`, `provider_unavailable`, `invalid_provider_output`, and others) without exposing provider response bodies.
- Provider output is rendered as text (React escapes it) and cannot change the verdict, score, decision source, or rule-based explanation. On any failure, the rule-based explanation remains visible and a notice is shown.
- The prompt marks the evidence as untrusted data and instructs the model not to follow instructions inside it. A per-user rate limiter (10 requests per 5 minutes by default) adds a second layer.
- Provider `429` responses are surfaced as rate limits; the app does not retry automatically.

Configuration is read from the backend process environment before startup. A `.env` file is not loaded automatically.

| Variable | Default | Purpose |
|---|---|---|
| `EXPLAIN_AI_ENABLED` | `false` | Must be `true` to enable the hosted adapter. |
| `EXPLAIN_AI_BASE_URL` | empty | OpenAI-compatible base URL, for example `https://your-provider.example/v1`. |
| `EXPLAIN_AI_MODEL` | empty | Model identifier expected by that provider. |
| `EXPLAIN_AI_API_KEY` | empty | Server-side key. Never commit it. |
| `EXPLAIN_AI_TIMEOUT_MS` | `12000` | Request timeout, clamped to 1,000-30,000 ms. |
| `EXPLAIN_AI_MAX_OUTPUT_CHARS` | `4000` | Total section budget, clamped to 500-12,000 characters. |

The provider-specific values are placeholders, not an endorsement or a default provider. If a different SDK or provider-specific client is required, review it and add it deliberately.

### Explanation tests

- `src/explanations/rules.test.js`: evidence separation, verdict/score preservation, mode parity, review/trusted-domain wording, missing evidence, failed-scan coverage, hosted redaction, prompt-injection text handling, and sanitisation.
- `src/components/GlossaryTerm.test.js`: hover, focus, tap, Escape, outside click, and unknown-term behavior.
- `src/components/ExplanationPanel.test.js`: default mode, persistence, consent gating, hosted success, and provider-failure fallback.
- `src/explanations/hosted.test.js`: consent enforcement, payload minimisation, and invalid-output rejection.
- `backend/explain.test.js`: configuration, sanitisation and finding-text redaction, prompt isolation, parsing and limits, timeout/429/500 mapping, consent, rate limits, and secret non-exposure.

## Dashboard and Analytics

The authenticated React dashboard presents scan totals, results, local scan history, model metrics, and an admin overview. The backend stores users and scan history in local JSON files created at startup; these files are excluded from version control.

## Requirements

- Windows 10/11
- Node.js 18 or newer
- Python 3.11 or newer (the pinned scikit-learn release requires a supported modern Python)
- Tesseract OCR at a standard install path or on `PATH` for screenshot analysis; the other features work without it

### Model Artifacts

URL prediction requires these six files in `ml-service/`, or in a directory named by `PHISHING_MODEL_DIR`:

`phishing_model.pkl`, `hgb_model.pkl`, `feature_names.pkl`, `deep_scaler.pkl`, `deep_feature_names.pkl`, and `deep_model.pt`.

The optional `email_text_model.pkl` enables the starter email-text score. `metrics.pkl` and `deep_metrics.json` enable the stored dashboard metrics. `dataset.csv` is optional and is used only for training-range checks; predictions do not require it.

Place the artifacts in `ml-service/`, or set the environment variable before starting the ML service:

```powershell
$env:PHISHING_MODEL_DIR = "C:\path\to\model-artifacts"
python api.py
```

Verify `http://127.0.0.1:5100/ready` returns `"ready": true` with an empty `missing` list. If required artifacts are absent, the service still starts, but URL endpoints return a model-unavailable response.

## Installation and Run

Install frontend dependencies from the project root:

```powershell
npm ci
```

Install backend dependencies:

```powershell
cd backend
npm ci
```

Create the Python environment and install ML dependencies:

```powershell
cd ..\ml-service
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Start each component in a separate PowerShell window, from the project root. If the model artifacts are outside `ml-service`, set `PHISHING_MODEL_DIR` in the ML service window first (see [Model Artifacts](#model-artifacts)):

```powershell
cd ml-service
.venv\Scripts\Activate.ps1
python api.py
```

```powershell
cd backend
npm start
```

```powershell
npm start
```

Open `http://localhost:3000`. Registration creates normal user accounts only; use the one-time environment-token bootstrap described in [Admin Monitoring and Critical Alerts](#admin-monitoring-and-critical-alerts) to promote the initial administrator. Local authentication is for demonstration only and is not production-grade.

## Admin Monitoring and Critical Alerts

Administrators use the existing login and bearer-session system. Public registration always creates a normal user. On a fresh installation with no administrator, register the intended account, set `ADMIN_SETUP_TOKEN` in the backend process environment, and restart the backend with that variable set. Promote the registered account once:

```powershell
$setupToken = [guid]::NewGuid().ToString('N')
$env:ADMIN_SETUP_TOKEN = $setupToken
Set-Location .\backend
npm start
```

In another PowerShell window, call the one-time setup route with the same secret (keep it out of browser code and source control):

```powershell
$setupToken = Read-Host 'Enter the one-time setup token from the backend window'
$headers = @{ 'x-admin-setup-token' = $setupToken }
Invoke-RestMethod -Method Post -Uri http://localhost:5000/auth/admin-setup `
	-Headers $headers -ContentType 'application/json' `
	-Body (@{ username = 'your-registered-username' } | ConvertTo-Json)
```

The setup route is disabled unless the backend environment contains the secret and returns `409` once an administrator exists. It cannot create an account or accept a role from public registration. Sign in again after promotion. If an administrator already exists, the setup route returns `409`; no bootstrap action is needed unless the administrator account is intentionally replaced.

The admin-only routes are `/admin/overview`, `/admin/users`, `/admin/users/:userId`, `/admin/users/:userId/scans`, `/admin/scans`, `/admin/scans/:scanId`, `/admin/alerts`, and `/admin/alerts/:alertId`. All require an authenticated admin session; a normal user receives `403`. Admin user serializers omit password hashes and tokens. Scan and alert views redact URL credentials and sensitive query parameters; scanned links are displayed as text and are never opened by the dashboard. The existing JSON files remain the persistent store, with `alerts.json` created on startup. Old records are retained; scan type is inferred only where existing result fields identify it, while unavailable historical user IDs, timestamps, and registration dates cannot be reconstructed.

Critical-alert rules are configured in the backend environment. Defaults are `CRITICAL_ALERT_MIN_SCORE=95`, `CRITICAL_ALERT_MIN_CONFIDENCE=70`, and `HIGH_RISK_SCORE=70`. A critical alert requires a final `phishing` verdict, the configured score and confidence minima, model disagreement no greater than 45 points when individual model scores are present, and at least one recognized independent indicator from the detector's reasons. `review`, trusted-domain outcomes, score-only results, and duplicate scan IDs do not create alerts. Alerts are dashboard notifications persisted in `backend/alerts.json`; no email or external notification is sent.

Historical scans are not backfilled automatically. An authenticated administrator can use **Backfill historical scans** in the Critical Alerts view; the dashboard asks for confirmation before sending `POST /admin/alerts/backfill` with `{ "confirm": true }`. The endpoint runs the same evaluator as new scans, appends only qualifying alerts, uses an existing `scanId` or legacy `id` for deduplication, preserves the stored scan timestamp, and never edits scan history or existing alerts. The response reports examined, qualified, created, already-alerted, and unevaluable counts. Missing risk, confidence, indicator text, or scan reference is not inferred; the corresponding record is reported as unevaluable where needed.

The storage and authentication implementation is intended for a local demonstration, not a multi-process or production deployment. Password hashing and in-memory sessions retain the existing project's behavior; use a production identity and durable database before exposing this service to untrusted networks.

## Tests

Run backend integration tests with `npm test` from `backend/`.

Run frontend checks with `npm test -- --watchAll=false --runInBand` and `npm run build` from the project root. Set `CI=true` in CI or non-interactive shells.

Run the ML suite from `ml-service` with the model directory configured:

```powershell
$env:PHISHING_MODEL_DIR = "C:\path\to\model-artifacts"
python -m unittest discover -v
```

The ML suite currently passes 125/125 with the configured artifacts and dataset. The supplied long `chatgpt.com` URL is expected to return `legitimate` through the trusted-domain override while retaining the underlying model prediction and ensemble score separately.

## Optional VirusTotal Integration

VirusTotal is disabled unless `VT_API_KEY` is set in the environment inherited by the ML service. `.env.example` is a blank template; the application does not automatically load a `.env` file. Do not commit real API keys.

## Example Test Cases

| Input | Expected demonstration result |
|---|---|
| `https://google.com` | Legitimate, very low risk (trusted-domain override) |
| `http://paypa1-verify-login.com/account` | Phishing, high risk with credential-harvesting indicators |
| Email/text file containing the phishing URL above | High file risk; embedded URL contributes to the result |
| Plain text with no links or phishing-style indicators | Low risk with an insufficient-indicators explanation |
| QR code containing a URL | Decoded URL is classified by the URL detector |

The suspicious domain is an example test input, not a hard-coded detector rule.

## Limitations

- Dataset duplicates can inflate random hold-out metrics; the supplied scores do not establish real-world performance.
- The email NLP model is a small starter/demo baseline.
- URL, email, and file rules can produce false positives and false negatives; a low score does not guarantee safety.
- File analysis does not execute or sandbox files and cannot reliably inspect every encoded, encrypted, or complex document format.
- Screenshot analysis is visual/structural only and does not establish destination safety.
- Domain lookups depend on network availability; VirusTotal additionally requires a user-provided key.
- Local authentication and JSON storage are for demonstration, not production use with real accounts or sensitive data.
- The deterministic explanation is English-only. Its schema carries a `locale` field so translations can be added later without changing the evidence contract.
- The optional hosted explanation can be wrong even when its input is correct, may be unavailable, and requires operator configuration. It cannot change the detector verdict or score.
- Explanations describe detector evidence; they do not establish intent or guarantee safety.

## Future Improvements

- Record dataset provenance and licensing, then evaluate with duplicate-aware and time-based splits.
- Train and validate email models using licensed, representative data.
- Add calibrated scores, broader regression tests, and more robust MIME/document parsing.
- Replace demo authentication and local JSON storage before production deployment.
- Evaluate reputation integrations and detection thresholds against independent data.
