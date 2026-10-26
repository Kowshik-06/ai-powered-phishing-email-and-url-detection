from http.server import BaseHTTPRequestHandler,HTTPServer
import json,base64,tempfile,os
try:
    import numpy as np
    import cv2
    _CV2_AVAILABLE = True
except Exception:
    np = None
    cv2 = None
    _CV2_AVAILABLE = False
from engine import predict_url,predict_email,decode_qr,metrics,analyze_attachment,domain_intelligence,analyze_screenshot,generate_report,model_readiness

def send(h,status,payload,ctype='application/json'):
    try:
        data=payload if isinstance(payload,bytes) else json.dumps(payload).encode()
    except Exception:
        data=json.dumps({'error':'internal_error'}).encode()
    h.send_response(status)
    h.send_header('Content-Type',ctype)
    h.send_header('Access-Control-Allow-Origin','*')
    h.send_header('Access-Control-Allow-Headers','Content-Type')
    h.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS')
    h.send_header('Content-Length',str(len(data)))
    h.end_headers()
    h.wfile.write(data)

def _unavailable_response(endpoint):
    readiness = model_readiness()
    missing = readiness.get('missing') or []
    return {
        'error': 'model_unavailable',
        'message': 'Required model artifacts are not available for this endpoint.',
        'endpoint': endpoint,
        'ready': bool(readiness.get('ready')),
        'url_ready': bool(readiness.get('url_ready')),
        'email_ready': bool(readiness.get('email_ready')),
        'missing': missing,
    }

class Handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self): send(self,200,{})
    def do_GET(self):
        try:
            if self.path=='/health':
                readiness = model_readiness()
                status = 200 if readiness.get('ready') else 503
                payload = {'status': 'ok' if status==200 else 'degraded', 'process': 'ok', 'readiness': readiness}
                send(self,status,payload)
                return
            if self.path=='/ready':
                readiness = model_readiness()
                status = 200 if readiness.get('ready') else 503
                send(self,status,{'ready': bool(readiness.get('ready')), 'readiness': readiness})
                return
            if self.path=='/metrics':
                readiness = model_readiness()
                if not readiness.get('ready'):
                    send(self,503,_unavailable_response('/metrics'))
                    return
                send(self,200,metrics())
                return
            else: send(self,404,{'error':'Not found'})
        except Exception:
            send(self,500,{'error':'internal_error'})
    def do_POST(self):
        tmp=None
        try:
            n=int(self.headers.get('Content-Length','0')); body=self.rfile.read(n); data=json.loads(body or '{}')
            if self.path=='/predict-url':
                readiness=model_readiness()
                if not readiness.get('url_ready'): send(self,503,_unavailable_response('/predict-url')); return
                out=predict_url(data.get('url',''))
            elif self.path=='/predict-email':
                readiness=model_readiness()
                if not readiness.get('email_ready'): send(self,503,_unavailable_response('/predict-email')); return
                out=predict_email(data.get('email',''))
            elif self.path=='/predict-qr':
                if not _CV2_AVAILABLE: send(self,503,_unavailable_response('/predict-qr')); return
                readiness=model_readiness()
                if not readiness.get('url_ready'): send(self,503,_unavailable_response('/predict-qr')); return
                raw=data.get('imageBase64',''); raw=raw.split(',',1)[-1]; raw_bytes=base64.b64decode(raw); fd,tmp=tempfile.mkstemp(suffix='.png'); os.close(fd)
                with open(tmp,'wb') as f:f.write(raw_bytes)
                img=cv2.imdecode(np.frombuffer(raw_bytes,np.uint8),cv2.IMREAD_COLOR)
                if img is None: raise ValueError('Invalid image data')
                cv2.imwrite(tmp,img); out=decode_qr(tmp)
            elif self.path=='/analyze-attachment':
                readiness=model_readiness()
                if not readiness.get('url_ready'): send(self,503,_unavailable_response('/analyze-attachment')); return
                raw=data.get('fileBase64',''); raw=raw.split(',',1)[-1]; name=data.get('filename','attachment'); suffix=os.path.splitext(name)[1] or '.bin'; fd,tmp=tempfile.mkstemp(suffix=suffix); os.close(fd)
                with open(tmp,'wb') as f:f.write(base64.b64decode(raw))
                out=analyze_attachment(tmp,name)
            elif self.path=='/domain-intelligence': out=domain_intelligence(data.get('domain',''))
            elif self.path=='/analyze-screenshot':
                if not _CV2_AVAILABLE: send(self,503,_unavailable_response('/analyze-screenshot')); return
                readiness=model_readiness()
                if not readiness.get('url_ready'): send(self,503,_unavailable_response('/analyze-screenshot')); return
                raw=data.get('imageBase64',''); raw=raw.split(',',1)[-1]; raw_bytes=base64.b64decode(raw); fd,tmp=tempfile.mkstemp(suffix='.png'); os.close(fd)
                with open(tmp,'wb') as f:f.write(raw_bytes)
                img=cv2.imdecode(np.frombuffer(raw_bytes,np.uint8),cv2.IMREAD_COLOR)
                if img is None: raise ValueError('Invalid image data')
                cv2.imwrite(tmp,img); out=analyze_screenshot(tmp)
            elif self.path=='/report': out=generate_report(data)
            else: send(self,404,{'error':'Not found'}); return
            send(self,200,out)
        except RuntimeError as e:
            if str(e) in ('url_models_unavailable','email_model_unavailable'):
                endpoint={'/predict-url':'/predict-url','/predict-email':'/predict-email'}.get(self.path,self.path)
                send(self,503,_unavailable_response(endpoint))
            else:
                send(self,400,{'error':'bad_request'})
        except Exception:
            send(self,400,{'error':'bad_request'})
        finally:
            if tmp:
                try: os.remove(tmp)
                except OSError: pass
    def log_message(self,*args): pass
if __name__=='__main__': HTTPServer(('127.0.0.1',5100),Handler).serve_forever()
