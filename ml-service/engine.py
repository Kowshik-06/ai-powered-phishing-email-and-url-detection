def predict_url(url):
    ensure_url_ready()
    url = url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = 'https://' + url
    f = _url_features(url)
    rf = float(RF.predict_proba(f)[0, 1])
    hp = float(HGB.predict_proba(f)[0, 1])
    dp = _deep_probability(f)
    host = (urlparse(url).hostname or '').lower().strip('.')
    ensemble = .8 * hp + .1 * rf + .1 * dp
    confidence = abs(ensemble - .5) * 2
    risk = round(ensemble * 100, 2)
    pred = 'phishing' if ensemble >= .5 else 'legitimate'
    fallback = confidence < .20 or max(rf, hp, dp) - min(rf, hp, dp) > .45
    if fallback:
        pred = 'suspicious' if 0.30 <= ensemble <= 0.70 else pred
    model_pred = pred
    heuristic_reasons = _reasons(url, f, rf, dp)
    reasons = heuristic_reasons[:]
    trusted = _is_trusted_host(host)
    range_violation = _training_range_violation(f)
    decision_source = 'model'
    threat_category = categorize(url)
    decision_explanation = None
    if trusted:
        pred = 'legitimate'
        decision_source = 'trusted-domain-override'
        risk = 1.0
        threat_category = 'Trusted Domain'
        reasons = ['Exact trusted-domain match or valid subdomain boundary; model prediction is retained separately.']
        decision_explanation = 'Exact trusted-domain match or valid subdomain boundary.'
    elif range_violation:
        name, value, bounds = range_violation
        pred = 'review'
        decision_source = 'outside-training-range'
        threat_category = 'Outside Training Range'
        decision_explanation = f'Model input {name}={value:g} is outside the observed training range {bounds[0]:g}-{bounds[1]:g}; manual review is required.'
        reasons.append(decision_explanation)
    score_meaning = 'Uncalibrated model ensemble score; not a probability of maliciousness.'
    if trusted:
        score_meaning = 'Trusted-domain decision; underlying model ensemble score is uncalibrated.'
    return {'type': pred, 'riskPercentage': risk, 'confidencePercentage': round(confidence * 100, 2), 'url': url, 'urlLength': len(url), 'hasHttps': url.lower().startswith('https://'), 'suspiciousKeywords': sum(k in url.lower() for k in KEYWORDS), 'specialChars': sum(not c.isalnum() and c not in ':/.' for c in url), 'models': {'randomForest': round(rf * 100, 2), 'histGradientBoosting': round(hp * 100, 2), 'deepLearning': round(dp * 100, 2), 'ensemble': round(ensemble * 100, 2)}, 'modelPrediction': model_pred, 'modelRiskPercentage': round(ensemble * 100, 2), 'decisionSource': decision_source, 'scoreMeaning': score_meaning, 'explanations': {'model': None, 'heuristic': heuristic_reasons, 'decision': decision_explanation}, 'reasons': reasons, 'threatCategory': threat_category}


def categorize(url):
    s = url.lower()
    if any(k in s for k in ['bank', 'wallet', 'payment', 'paypal', 'upi']):
        return 'Financial Phishing'
    if any(k in s for k in ['login', 'signin', 'account', 'password', 'verify']):
        return 'Credential Harvesting'
    if any(k in s for k in ['download', 'update', 'install']):
        return 'Malware/Update Lure'
    return 'Suspicious URL' if 'phishing' in s else 'General Web Threat'


def _extract_urls(text):
    return re.findall(r'https?://[^\s<>"\']+', text or '', flags=re.I)


def predict_email(raw):
    ensure_email_ready()
    if not raw.strip():
        raise ValueError('Email content is required')
    msg = BytesParser(policy=policy.default).parsebytes(raw.encode('utf-8', 'ignore'))
    subject = msg.get('subject', '') or ''
    sender = msg.get('from', '') or ''
    reply = msg.get('reply-to', '') or ''
    body = '\n'.join(p.get_content() for p in msg.walk() if p.get_content_type() in ('text/plain', 'text/html') and not p.is_multipart())
    urls = _extract_urls(subject + '\n' + body)
    url_results = [predict_url(u) for u in urls[:10]]
    text = (subject + ' ' + body).lower()
    urgent = sum(k in text for k in ['urgent', 'immediately', 'suspended', 'verify now', 'act now', 'within 24 hours'])
    credential = sum(k in text for k in ['password', 'login', 'otp', 'verification', 'account'])
    text_score = float(EMAIL_MODEL.predict_proba([subject + ' ' + body])[0, 1])
    score = 0.10 + min(0.35, urgent * .08) + min(0.25, credential * .04)
    score = 0.65 * score + 0.35 * text_score
    if sender and reply and sender.split('@')[-1].lower() != reply.split('@')[-1].lower():
        score += .18
    if url_results:
        score = max(score, max(r['riskPercentage'] for r in url_results) / 100 * .75)
    score = min(.99, score)
    label = 'phishing' if score >= .55 else ('suspicious' if score >= .30 else 'legitimate')
    reasons = []
    if urgent:
        reasons.append('Urgency/pressure language detected.')
    if credential:
        reasons.append('Credential or verification language detected.')
    if sender and reply and sender.split('@')[-1].lower() != reply.split('@')[-1].lower():
        reasons.append('From and Reply-To domains differ.')
    if url_results and any(r['type'] in ('phishing', 'suspicious') for r in url_results):
        reasons.append('Embedded URL analysis produced a threat signal.')
    if not reasons:
        reasons.append('No strong phishing indicators were found by the hybrid email rules.')
    return {'type': label, 'riskPercentage': round(score * 100, 2), 'confidencePercentage': round(abs(score - .5) * 200, 2), 'subject': subject, 'sender': sender, 'replyTo': reply, 'urlCount': len(urls), 'urls': url_results, 'headerChecks': {'spf': msg.get('Received-SPF', 'not present'), 'dkim': msg.get('DKIM-Signature', 'not present'), 'dmarc': msg.get('Authentication-Results', 'not present')}, 'reasons': reasons, 'threatCategory': 'Email Phishing' if label != 'legitimate' else 'No Strong Threat', 'emailTextModelScore': round(text_score * 100, 2)}


def decode_qr(path):
    import cv2
    img = cv2.imread(path)
    if img is None:
        raise ValueError('Could not read image')
    data, _, _ = cv2.QRCodeDetector().detectAndDecode(img)
    if not data:
        raise ValueError('No readable QR code found')
    if re.match(r'^https?://', data, re.I):
        result = predict_url(data)
        result.update({'decodedData': data, 'scanType': 'qr'})
        return result
    return {'type': 'suspicious' if data else 'legitimate', 'riskPercentage': 50 if data else 0, 'confidencePercentage': 0, 'decodedData': data, 'scanType': 'qr', 'reasons': ['QR code decoded to non-URL content; inspect before opening.']}


def metrics():
    ensure_url_ready()
    out = {}
    if _metrics is not None:
        out = dict(_metrics)
    elif os.path.exists(os.path.join(MODEL_DIR, METRICS_FILE)):
        try:
            out = joblib.load(os.path.join(MODEL_DIR, METRICS_FILE))
        except Exception:
            out = {}
    if _deep_metrics is not None:
        out['deepLearning'] = _deep_metrics
    elif os.path.exists(os.path.join(MODEL_DIR, DEEP_METRICS_FILE)):
        try:
            with open(os.path.join(MODEL_DIR, DEEP_METRICS_FILE)) as f:
                out['deepLearning'] = json.load(f)
        except Exception:
            pass
    if not out:
        raise RuntimeError('metrics_unavailable')
    return out
import os, re, json, base64, joblib, numpy as np, pandas as pd, torch
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
from html import unescape
from torch import nn
import pytesseract
from url_features import extract_features

for candidate in [
    r'C:\Program Files\Tesseract-OCR\tesseract.exe',
    os.path.join(os.path.expanduser('~'), 'AppData', 'Local', 'Tesseract-OCR', 'tesseract.exe')
]:
    if os.path.exists(candidate):
        pytesseract.pytesseract.tesseract_cmd = candidate
        break

BASE = os.path.dirname(os.path.abspath(__file__))
MODEL_DIR = os.environ.get('PHISHING_MODEL_DIR') or BASE

REQUIRED_URL_MODELS = ['phishing_model.pkl', 'hgb_model.pkl', 'feature_names.pkl', 'deep_scaler.pkl', 'deep_feature_names.pkl', 'deep_model.pt']
EMAIL_MODEL_FILE = 'email_text_model.pkl'
METRICS_FILE = 'metrics.pkl'
DEEP_METRICS_FILE = 'deep_metrics.json'
DATASET_PATH = os.path.join(MODEL_DIR, 'dataset.csv')

_rf = None
_hgb = None
_features = None
_scaler = None
_deep_features = None
_deep = None
_email_model = None
_metrics = None
_deep_metrics = None
_training_ranges = {}
_deep_mlp = None

MODEL_STATUS = {
    'base': MODEL_DIR,
    'ready': False,
    'reason': 'not_initialized',
    'missing': [],
    'loaded': [],
    'url_ready': False,
    'email_ready': False,
    'endpoints': {}
}

def _missing_required():
    missing = []
    for name in REQUIRED_URL_MODELS:
        if not os.path.exists(os.path.join(MODEL_DIR, name)):
            missing.append(name)
    return missing


def _load_models():
    global _rf, _hgb, _features, _scaler, _deep_features, _deep, _email_model, _metrics, _deep_metrics, _training_ranges, _deep_mlp, MODEL_STATUS
    missing = _missing_required()
    if missing:
        MODEL_STATUS.update({
            'ready': False,
            'reason': 'missing_artifacts',
            'missing': missing,
            'loaded': [],
            'url_ready': False,
            'email_ready': False,
        })
        return
    try:
        _rf = joblib.load(os.path.join(MODEL_DIR, 'phishing_model.pkl'))
        _hgb = joblib.load(os.path.join(MODEL_DIR, 'hgb_model.pkl'))
        _features = joblib.load(os.path.join(MODEL_DIR, 'feature_names.pkl'))
        _scaler = joblib.load(os.path.join(MODEL_DIR, 'deep_scaler.pkl'))
        _deep_features = joblib.load(os.path.join(MODEL_DIR, 'deep_feature_names.pkl'))
        class MLP(nn.Module):
            def __init__(self, n):
                super().__init__()
                self.net = nn.Sequential(nn.Linear(n, 64), nn.ReLU(), nn.Dropout(0.15), nn.Linear(64, 32), nn.ReLU(), nn.Linear(32, 1))
            def forward(self, x):
                return self.net(x).squeeze(1)
        _deep_mlp = MLP(len(_deep_features))
        _deep_mlp.load_state_dict(torch.load(os.path.join(MODEL_DIR, 'deep_model.pt'), map_location='cpu'))
        _deep_mlp.eval()
        _deep = _deep_mlp
        if os.path.exists(os.path.join(MODEL_DIR, EMAIL_MODEL_FILE)):
            _email_model = joblib.load(os.path.join(MODEL_DIR, EMAIL_MODEL_FILE))
        if os.path.exists(os.path.join(MODEL_DIR, METRICS_FILE)):
            _metrics = joblib.load(os.path.join(MODEL_DIR, METRICS_FILE))
        if os.path.exists(os.path.join(MODEL_DIR, DEEP_METRICS_FILE)):
            try:
                with open(os.path.join(MODEL_DIR, DEEP_METRICS_FILE)) as f:
                    _deep_metrics = json.load(f)
            except Exception:
                _deep_metrics = None
        if os.path.exists(DATASET_PATH) and _features is not None:
            try:
                _training_data = pd.read_csv(DATASET_PATH, usecols=_features)
                _training_ranges = {name: (float(_training_data[name].min()), float(_training_data[name].max())) for name in _features}
                del _training_data
            except Exception:
                _training_ranges = {}
        MODEL_STATUS.update({
            'ready': True,
            'reason': 'ok',
            'missing': [],
            'loaded': REQUIRED_URL_MODELS + ([EMAIL_MODEL_FILE] if _email_model is not None else []) + ([METRICS_FILE] if _metrics is not None else []),
            'url_ready': True,
            'email_ready': _email_model is not None,
        })
    except Exception as e:
        MODEL_STATUS.update({
            'ready': False,
            'reason': 'load_error',
            'missing': [],
            'loaded': [],
            'url_ready': False,
            'email_ready': False,
        })


_load_models()

# Backwards compatible aliases
RF = _rf
HGB = _hgb
FEATURES = _features
SCALER = _scaler
DEEP_FEATURES = _deep_features
EMAIL_MODEL = _email_model
DEEP = _deep
TRUSTED_DOMAINS = {'google.com','github.com','microsoft.com','apple.com','amazon.com','youtube.com','linkedin.com','chatgpt.com','openai.com','anthropic.com','claude.ai','perplexity.ai','example.com','example.org','example.net'}
KEYWORDS = ['login','secure','bank','verify','update','account','signin','password','wallet','payment','confirm','suspended','urgent']

# Ensure aliases reflect loaded state
RF = _rf
HGB = _hgb
FEATURES = _features
SCALER = _scaler
DEEP_FEATURES = _deep_features
EMAIL_MODEL = _email_model
DEEP = _deep

def model_readiness():
    return dict(MODEL_STATUS)


def ensure_url_ready():
    if not MODEL_STATUS.get('url_ready'):
        raise RuntimeError('url_models_unavailable')


def ensure_email_ready():
    if not MODEL_STATUS.get('email_ready'):
        raise RuntimeError('email_model_unavailable')


def _url_features(url):
    ensure_url_ready()
    f = extract_features(url)
    return f[FEATURES]


def _deep_probability(f):
    ensure_url_ready()
    x = SCALER.transform(f[DEEP_FEATURES].astype(float).values)
    with torch.no_grad():
        p = float(torch.sigmoid(DEEP(torch.tensor(x, dtype=torch.float32))).item())
    return p


def _hostname_hyphen_count(url):
    parsed = urlparse(url if '://' in url else 'https://'+url)
    return (parsed.hostname or '').count('-')


def _is_trusted_host(host):
    host = (host or '').lower().strip('.')
    return any(host == domain or host.endswith('.'+domain) for domain in TRUSTED_DOMAINS)


def _training_range_violation(f):
    if not _training_ranges:
        return None
    for name, value in f.iloc[0].items():
        bounds = _training_ranges.get(name)
        if bounds and (float(value) < bounds[0] or float(value) > bounds[1]):
            return name, float(value), bounds
    return None


def _reasons(url, f, rfp, deepp):
    reasons = []
    parsed = urlparse(url if '://' in url else 'http://'+url)
    host = parsed.hostname or ''
    if '@' in url:
        reasons.append('URL contains an @ symbol, which can hide the true destination.')
    if not url.lower().startswith('https://'):
        reasons.append('URL does not use HTTPS.')
    if f.iloc[0]['sensitive_words_count'] >= 2:
        reasons.append('Multiple security/account-related keywords detected in the URL.')
    if _hostname_hyphen_count(url) >= 3:
        reasons.append('The hostname contains multiple hyphens; inspect it for a look-alike domain.')
    if len(host.split('.')) >= 4:
        reasons.append('Deep subdomain structure detected.')
    if any(c in host for c in ['xn--']):
        reasons.append('Punycode/IDN hostname detected; inspect carefully for look-alikes.')
    return reasons
    if credential: reasons.append('Credential or verification language detected.')
    if sender and reply and sender.split('@')[-1].lower()!=reply.split('@')[-1].lower(): reasons.append('From and Reply-To domains differ.')
    if url_results and any(r['type'] in ('phishing','suspicious') for r in url_results): reasons.append('Embedded URL analysis produced a threat signal.')
    if not reasons: reasons.append('No strong phishing indicators were found by the hybrid email rules.')
    return {'type':label,'riskPercentage':round(score*100,2),'confidencePercentage':round(abs(score-.5)*200,2),'subject':subject,'sender':sender,'replyTo':reply,'urlCount':len(urls),'urls':url_results,'headerChecks':{'spf':msg.get('Received-SPF','not present'),'dkim':msg.get('DKIM-Signature','not present'),'dmarc':msg.get('Authentication-Results','not present')},'reasons':reasons,'threatCategory':'Email Phishing' if label!='legitimate' else 'No Strong Threat','emailTextModelScore':round(text_score*100,2)}

def decode_qr(path):
    import cv2
    img=cv2.imread(path)
    if img is None: raise ValueError('Could not read image')
    data,_,_=cv2.QRCodeDetector().detectAndDecode(img)
    if not data: raise ValueError('No readable QR code found')
    if re.match(r'^https?://',data,re.I):
        result=predict_url(data); result.update({'decodedData':data,'scanType':'qr'}); return result
    return {'type':'suspicious' if data else 'legitimate','riskPercentage':50 if data else 0,'confidencePercentage':0,'decodedData':data,'scanType':'qr','reasons':['QR code decoded to non-URL content; inspect before opening.']}

def metrics():
    ensure_url_ready()
    out=dict(_metrics) if _metrics is not None else {}
    if _deep_metrics is not None:
        out['deepLearning']=_deep_metrics
    elif os.path.exists(os.path.join(MODEL_DIR,'deep_metrics.json')):
        with open(os.path.join(MODEL_DIR,'deep_metrics.json')) as f: out['deepLearning']=json.load(f)
    if not out: raise RuntimeError('metrics_unavailable')
    return out

# ---- Additional defensive-analysis modules ----
def analyze_attachment(path, filename):
    import hashlib, zipfile
    ext=os.path.splitext(filename.lower())[1]
    data=open(path,'rb').read()
    sha256=hashlib.sha256(data).hexdigest()
    risky={'.exe','.dll','.scr','.bat','.cmd','.ps1','.vbs','.js','.jar','.msi','.hta','.iso','.img'}
    macro_ext={'.docm','.xlsm','.pptm'}
    reasons=[]; risk=5
    if ext in risky: risk+=70; reasons.append('Executable or script attachment type detected.')
    if ext in macro_ext: risk+=45; reasons.append('Office macro-enabled document detected.')
    if ext in {'.zip','.rar','.7z'}:
        try:
            if ext=='.zip':
                with zipfile.ZipFile(path) as z:
                    names=z.namelist(); dangerous=[n for n in names if os.path.splitext(n.lower())[1] in risky]
                    if dangerous: risk+=65; reasons.append('Archive contains executable/script content.')
        except Exception: reasons.append('Archive could not be fully inspected.')
    if b'vbaProject.bin' in data: risk+=45; reasons.append('VBA macro payload marker detected.')
    urls=re.findall(rb'https?://[^\s\x00\"\'<>]+',data,re.I)[:10]
    url_results=[predict_url(u.decode('utf-8','ignore')) for u in urls]
    if url_results: risk=max(risk,max(x['riskPercentage'] for x in url_results))
    risk=min(99,round(risk,2)); label='phishing' if risk>=70 else ('suspicious' if risk>=30 else 'legitimate')
    if any(result['type'] in ('phishing','suspicious') for result in url_results):
        reasons.append('Suspicious embedded URL detected by the existing URL analysis.')
    text=data.decode('utf-8','ignore').lower()
    suspicious_phrases=('verify your account','confirm your account','update your account','login to your account','sign in to your account','account suspended','account security','security alert','verify your identity','confirm your identity','reset your password','update your password','password has expired')
    if any(phrase in text for phrase in suspicious_phrases):
        reasons.append('Suspicious account/security language detected.')
    if not reasons: reasons.append('No embedded URLs or high-risk attachment indicators were detected.')
    return {'type':label,'riskPercentage':risk,'confidencePercentage':round(abs(risk/100-.5)*200,2),'filename':filename,'sizeBytes':len(data),'sha256':sha256,'extension':ext,'embeddedUrls':url_results,'reasons':reasons,'threatCategory':'Malicious Attachment' if label!='legitimate' else 'No Strong Threat'}

def domain_intelligence(domain):
    import socket
    raw=(domain or '').strip()
    if not raw: raise ValueError('Domain is required')
    parsed=urlparse(raw if '://' in raw else 'https://'+raw)
    d=(parsed.hostname or raw.lower().replace('https://','').replace('http://','').split('/')[0].split(':')[0]).strip('.').lower()
    if not d: raise ValueError('Domain is required')
    out={'domain':d,'resolvedIps':[],'dnsAvailable':False,'rdap':None,'virusTotal':None,'notes':[]}
    try:
        out['resolvedIps']=sorted(set(x[4][0] for x in socket.getaddrinfo(d,None))); out['dnsAvailable']=bool(out['resolvedIps'])
    except Exception: out['notes'].append('DNS resolution unavailable in this environment.')
    import urllib.request
    try:
        req=urllib.request.Request('https://rdap.org/domain/'+d,headers={'User-Agent':'PhishingDetection/1.0'})
        with urllib.request.urlopen(req,timeout=4) as r: out['rdap']=json.loads(r.read().decode())
    except Exception: out['notes'].append('RDAP lookup unavailable; local analysis remains available.')
    key=os.getenv('VT_API_KEY')
    if key:
        try:
            req=urllib.request.Request('https://www.virustotal.com/api/v3/domains/'+d,headers={'x-apikey':key,'User-Agent':'PhishingDetection/1.0'})
            with urllib.request.urlopen(req,timeout=6) as r:
                j=json.loads(r.read().decode()); out['virusTotal']=j.get('data',{}).get('attributes',{})
        except Exception: out['notes'].append('VirusTotal lookup failed or was rate-limited.')
    else: out['notes'].append('VirusTotal is disabled until VT_API_KEY is configured.')
    return out

def analyze_screenshot(path):
    import cv2,hashlib
    img=cv2.imread(path)
    if img is None: raise ValueError('Invalid image')
    h,w=img.shape[:2]; gray=cv2.cvtColor(img,cv2.COLOR_BGR2GRAY); edges=cv2.Canny(gray,80,180)
    edge_density=float((edges>0).mean())
    try:
        text=pytesseract.image_to_string(img).strip()
    except pytesseract.pytesseract.TesseractNotFoundError as exc:
        raise ValueError('OCR engine is not available on this machine; screenshot text cannot be read.') from exc
    except Exception as exc:
        raise ValueError('OCR failed to read the screenshot: '+str(exc)) from exc
    if not text:
        return {'type':'review','riskPercentage':0,'confidencePercentage':0,'width':w,'height':h,'edgeDensity':round(edge_density,4),'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest(),'ocrText':'','ocrUrls':[],'visualAssessment':'No readable text detected','reasons':['No readable text could be extracted from the screenshot.'], 'limitations':['Screenshot analysis cannot determine whether the page is safe without readable text or a destination URL.']}

    urls=_extract_urls(text)
    url_results=[predict_url(url) for url in urls]
    lower=text.lower()
    urgent=any(x in lower for x in ['urgent','immediately','act now','verify now','within 24 hours','account suspended'])
    verification=any(x in lower for x in ['verify your account','verify your identity','confirm your account','confirm your identity','security alert'])
    password=any(x in lower for x in ['password','passcode','reset your password','login','sign in'])
    payment=any(x in lower for x in ['payment','pay now','checkout','bank account','card details','wire transfer'])
    brands=['paypal','apple','microsoft','amazon','google','github','netflix','dropbox','bank of america','visa','mastercard']
    brand_matches=[brand for brand in brands if brand in lower]
    brand_impersonation=[]
    for brand in brand_matches:
        if urls and not any(brand in urlparse(url).hostname.lower() for url in urls):
            brand_impersonation.append(brand)
    indicator_score=0
    indicator_reasons=[]
    if urgent: indicator_score+=20; indicator_reasons.append('Urgent or time-pressure language detected in screenshot text.')
    if verification: indicator_score+=20; indicator_reasons.append('Account or identity verification request detected.')
    if password: indicator_score+=20; indicator_reasons.append('Password or login request detected.')
    if payment: indicator_score+=20; indicator_reasons.append('Payment or checkout request detected.')
    if brand_impersonation: indicator_score+=15; indicator_reasons.append('Brand impersonation wording detected without a matching brand URL.')

    url_risk=max((result['riskPercentage'] for result in url_results), default=0)
    url_type=max(url_results, key=lambda result: result['riskPercentage'])['type'] if url_results else 'review'
    risk=max(url_risk, indicator_score)
    if url_results and url_type in ('phishing','suspicious'):
        risk=max(risk, url_risk)
    if url_results and url_type=='legitimate' and not indicator_score:
        result_type='legitimate'
    elif indicator_score>=40: result_type='phishing'
    elif risk>=30: result_type='suspicious'
    else: result_type='review'
    reasons=indicator_reasons[:]
    if url_results:
        reasons.extend(f'URL analysis: {result["type"]} ({result["riskPercentage"]}%)' for result in url_results)
        if any(result['type'] in ('phishing','suspicious') for result in url_results): reasons.append('Screenshot contains a URL that produced a threat signal through the existing URL detector.')
    if not reasons: reasons.append('No strong phishing indicators were found in the extracted screenshot text.')
    confidence=round(min(98, max(20, 50+indicator_score*.25+max((result['confidencePercentage'] for result in url_results),default=0)*.25)),2)
    return {'type':result_type,'riskPercentage':round(min(99,risk),2),'confidencePercentage':confidence,'width':w,'height':h,'edgeDensity':round(edge_density,4),'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest(),'ocrText':text,'ocrUrls':urls,'urlResults':url_results,'visualAssessment':'Text extracted from screenshot','reasons':reasons,'scanType':'screenshot','screenshotIndicators':{'urgent':urgent,'verification':verification,'password':password,'payment':payment,'brandImpersonation':bool(brand_impersonation),'suspiciousUrls':bool(url_results and any(result['type'] in ('phishing','suspicious') for result in url_results))}, 'limitations':['Screenshot text analysis is an indicator, not proof of safety or maliciousness.']}

def generate_report(data):
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
    import io,datetime
    b=io.BytesIO(); c=canvas.Canvas(b,pagesize=A4); width,height=A4; y=height-20*mm
    c.setFont('Helvetica-Bold',18); c.drawString(20*mm,y,'AI-Powered Phishing Email and URL Detection'); y-=10*mm
    c.setFont('Helvetica',10); c.drawString(20*mm,y,'Threat Analysis Report'); y-=8*mm
    for k,v in data.items():
        if k in ('reasons','models','urls'): continue
        line=f'{k}: {str(v)[:130]}'; c.drawString(20*mm,y,line); y-=6*mm
        if y<20*mm: c.showPage(); y=height-20*mm
    if data.get('reasons'):
        c.setFont('Helvetica-Bold',11); c.drawString(20*mm,y,'Detection Reasons'); y-=6*mm; c.setFont('Helvetica',10)
        for r in data['reasons'][:12]: c.drawString(24*mm,y,'- '+str(r)[:115]); y-=5*mm
    c.setFont('Helvetica',8); c.drawString(20*mm,10*mm,'Generated '+datetime.datetime.now().isoformat(timespec='seconds'))
    c.save(); return {'pdfBase64':base64.b64encode(b.getvalue()).decode()}
