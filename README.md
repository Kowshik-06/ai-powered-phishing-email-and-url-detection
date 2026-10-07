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

These results come from a random stratified split of the engineered-feature dataset. It contains 2,488 rows and 1,134 duplicate rows, so the scores may overstate generalization to new domains. They are evaluation results, not a real-world accuracy guarantee. The dataset is not included until its source and redistribution terms are documented; the trained model artifacts are retained for inference.

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
- File risk starts at a low baseline, adds attachment-type/content indicators, and is raised by suspicious embedded URL risk.
- Results include human-readable indicators such as missing HTTPS, phishing-style account/security language, and suspicious embedded URLs. Reasons describe detected signals; they do not prove intent.

## Dashboard and Analytics

The authenticated React dashboard presents scan totals, results, local scan history, model metrics, and an admin overview. The backend stores users and scan history in local JSON files created at startup; these files are excluded from version control.

## Requirements

- Windows 10/11
- Node.js 18 or newer
- Python 3.11 or newer (the pinned scikit-learn release requires a supported modern Python)

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

Start each component in a separate PowerShell window, from the project root:

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

Open `http://localhost:3000`. The first account registered in a fresh local installation receives the admin role. Local authentication is for demonstration only and is not production-grade.

Alternatively, run `run_all.bat` from Windows. It opens separate command windows and runs dependency installation commands before starting the services.

### Optional VirusTotal Integration

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

## Future Improvements

- Record dataset provenance and licensing, then evaluate with duplicate-aware and time-based splits.
- Train and validate email models using licensed, representative data.
- Add calibrated scores, broader regression tests, and more robust MIME/document parsing.
- Replace demo authentication and local JSON storage before production deployment.
- Evaluate reputation integrations and detection thresholds against independent data.
