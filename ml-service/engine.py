import os, re, json, base64, joblib, numpy as np, pandas as pd, torch
from urllib.parse import urlparse
from email import policy
from email.parser import BytesParser
from html import unescape
from torch import nn
from url_features import extract_features

BASE=os.path.dirname(os.path.abspath(__file__))
RF=joblib.load(os.path.join(BASE,'phishing_model.pkl'))
HGB=joblib.load(os.path.join(BASE,'hgb_model.pkl'))
FEATURES=joblib.load(os.path.join(BASE,'feature_names.pkl'))
SCALER=joblib.load(os.path.join(BASE,'deep_scaler.pkl'))
DEEP_FEATURES=joblib.load(os.path.join(BASE,'deep_feature_names.pkl'))

class MLP(nn.Module):
    def __init__(self,n):
        super().__init__(); self.net=nn.Sequential(nn.Linear(n,64),nn.ReLU(),nn.Dropout(.15),nn.Linear(64,32),nn.ReLU(),nn.Linear(32,1))
    def forward(self,x): return self.net(x).squeeze(1)

EMAIL_MODEL=joblib.load(os.path.join(BASE,'email_text_model.pkl')) if os.path.exists(os.path.join(BASE,'email_text_model.pkl')) else None
DEEP=MLP(len(DEEP_FEATURES)); DEEP.load_state_dict(torch.load(os.path.join(BASE,'deep_model.pt'),map_location='cpu')); DEEP.eval()

KEYWORDS=['login','secure','bank','verify','update','account','signin','password','wallet','payment','confirm','suspended','urgent']

def _url_features(url):
    f=extract_features(url)
    return f[FEATURES]

def _deep_probability(f):
    x=SCALER.transform(f[DEEP_FEATURES].astype(float).values)
    with torch.no_grad(): p=float(torch.sigmoid(DEEP(torch.tensor(x,dtype=torch.float32))).item())
    return p

def _reasons(url,f,rfp,deepp):
    reasons=[]; parsed=urlparse(url if '://' in url else 'http://'+url)
    host=parsed.hostname or ''
    if '@' in url: reasons.append('URL contains an @ symbol, which can hide the true destination.')
    if len(url)>75: reasons.append('Unusually long URL.')
    if not url.lower().startswith('https://'): reasons.append('URL does not use HTTPS.')
    if f.iloc[0]['sensitive_words_count']>=2: reasons.append('Multiple security/account-related keywords detected.')
    if f.iloc[0]['nb_hyphens']>=3: reasons.append('Many hyphens increase the likelihood of look-alike domains.')
    if len(host.split('.'))>=4: reasons.append('Deep subdomain structure detected.')
    if any(c in host for c in ['xn--']): reasons.append('Punycode/IDN hostname detected; inspect carefully for look-alikes.')
    if not reasons: reasons.append('No strong lexical red flags were detected by the rule layer.')
    return reasons

def predict_url(url):
    url=url.strip()
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://',url): url='https://'+url
    f=_url_features(url)
    rf=float(RF.predict_proba(f)[0,1]); hp=float(HGB.predict_proba(f)[0,1]); dp=_deep_probability(f)
    host=(urlparse(url).hostname or '').lower().strip('.')
    trusted={'google.com','www.google.com','github.com','www.github.com','microsoft.com','www.microsoft.com','apple.com','www.apple.com','amazon.com','www.amazon.com','youtube.com','www.youtube.com','linkedin.com','www.linkedin.com'}
    if host in trusted or any(host.endswith('.'+d) for d in trusted):
        return {'type':'legitimate','riskPercentage':1.0,'confidencePercentage':98.0,'url':url,'urlLength':len(url),'hasHttps':url.lower().startswith('https://'),'suspiciousKeywords':0,'specialChars':sum(not c.isalnum() and c not in ':/.' for c in url),'models':{'randomForest':round(rf*100,2),'histGradientBoosting':round(hp*100,2),'deepLearning':round(dp*100,2),'ensemble':1.0},'reasons':['Recognized trusted high-profile domain; model score retained for audit but safety override applied.'],'threatCategory':'Trusted Domain'}
    # Ensemble gives the baseline model more weight because it performs better on the held-out set.
    ensemble=.8*hp+.1*rf+.1*dp
    confidence=abs(ensemble-.5)*2
    risk=round(ensemble*100,2)
    pred='phishing' if ensemble>=.5 else 'legitimate'
    # fallback: if models disagree strongly and confidence is low, flag for review rather than forcing a false certainty.
    fallback=confidence<.20 or max(rf,hp,dp)-min(rf,hp,dp)>.45
    if fallback: pred='suspicious' if 0.30<=ensemble<=0.70 else pred
    return {'type':pred,'riskPercentage':risk,'confidencePercentage':round(confidence*100,2),'url':url,'urlLength':len(url),'hasHttps':url.lower().startswith('https://'),'suspiciousKeywords':sum(k in url.lower() for k in KEYWORDS),'specialChars':sum(not c.isalnum() and c not in ':/.' for c in url),'models':{'randomForest':round(rf*100,2),'histGradientBoosting':round(hp*100,2),'deepLearning':round(dp*100,2),'ensemble':risk},'reasons':_reasons(url,f,rf,dp),'threatCategory':categorize(url)}

def categorize(url):
    s=url.lower()
    if any(k in s for k in ['bank','wallet','payment','paypal','upi']): return 'Financial Phishing'
    if any(k in s for k in ['login','signin','account','password','verify']): return 'Credential Harvesting'
    if any(k in s for k in ['download','update','install']): return 'Malware/Update Lure'
    return 'Suspicious URL' if 'phishing' in s else 'General Web Threat'

def _extract_urls(text): return re.findall(r'https?://[^\s<>"\']+',text or '',flags=re.I)

def predict_email(raw):
    if not raw.strip(): raise ValueError('Email content is required')
    msg=BytesParser(policy=policy.default).parsebytes(raw.encode('utf-8','ignore'))
    subject=msg.get('subject','') or ''; sender=msg.get('from','') or ''; reply=msg.get('reply-to','') or ''
    body='\n'.join(p.get_content() for p in msg.walk() if p.get_content_type() in ('text/plain','text/html') and not p.is_multipart())
    urls=_extract_urls(subject+'\n'+body)
    url_results=[predict_url(u) for u in urls[:10]]
    text=(subject+' '+body).lower()
    urgent=sum(k in text for k in ['urgent','immediately','suspended','verify now','act now','within 24 hours'])
    credential=sum(k in text for k in ['password','login','otp','verification','account'])
    auth_fail=sum(1 for h in ['spf','dkim','dmarc'] if ('pass' not in str(msg.get(h,'' )).lower()))
    text_score=float(EMAIL_MODEL.predict_proba([subject+' '+body])[0,1]) if EMAIL_MODEL else 0.5
    score=0.10+min(0.35,urgent*.08)+min(0.25,credential*.04)
    score=0.65*score+0.35*text_score
    if sender and reply and sender.split('@')[-1].lower()!=reply.split('@')[-1].lower(): score+=.18
    if url_results: score=max(score,max(r['riskPercentage'] for r in url_results)/100*.75)
    score=min(.99,score)
    label='phishing' if score>=.55 else ('suspicious' if score>=.30 else 'legitimate')
    reasons=[]
    if urgent: reasons.append('Urgency/pressure language detected.')
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
    out=joblib.load(os.path.join(BASE,'metrics.pkl'))
    with open(os.path.join(BASE,'deep_metrics.json')) as f: out['deepLearning']=json.load(f)
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
    d=domain.strip().lower().replace('https://','').split('/')[0].split(':')[0]
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
    edge_density=float((edges>0).mean()); text_hint='High visual complexity' if edge_density>.12 else 'Low visual complexity'
    reasons=[]
    if edge_density>.18: reasons.append('Dense edges/text-like regions detected; inspect branding and links carefully.')
    else: reasons.append('Screenshot structure is visually simple; image-only analysis cannot verify link destinations.')
    return {'type':'review','riskPercentage':0,'confidencePercentage':0,'width':w,'height':h,'edgeDensity':round(edge_density,4),'sha256':hashlib.sha256(open(path,'rb').read()).hexdigest(),'visualAssessment':text_hint,'reasons':reasons,'limitations':['Screenshot analysis does not prove a page is safe. URL/domain analysis should be used when the destination is available.']}

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
