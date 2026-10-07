from http.server import BaseHTTPRequestHandler,HTTPServer
import json,base64,tempfile,os,numpy as np,cv2
from engine import predict_url,predict_email,decode_qr,metrics,analyze_attachment,domain_intelligence,analyze_screenshot,generate_report

def send(h,status,payload,ctype='application/json'):
    data=payload if isinstance(payload,bytes) else json.dumps(payload).encode(); h.send_response(status); h.send_header('Content-Type',ctype); h.send_header('Access-Control-Allow-Origin','*'); h.send_header('Access-Control-Allow-Headers','Content-Type'); h.send_header('Access-Control-Allow-Methods','GET,POST,OPTIONS'); h.send_header('Content-Length',str(len(data))); h.end_headers(); h.wfile.write(data)
class Handler(BaseHTTPRequestHandler):
    def do_OPTIONS(self): send(self,200,{})
    def do_GET(self):
        try:
            if self.path=='/metrics': send(self,200,metrics())
            else: send(self,404,{'error':'Not found'})
        except Exception as e: send(self,500,{'error':str(e)})
    def do_POST(self):
        tmp=None
        try:
            n=int(self.headers.get('Content-Length','0')); body=self.rfile.read(n); data=json.loads(body or '{}')
            if self.path=='/predict-url': out=predict_url(data.get('url',''))
            elif self.path=='/predict-email': out=predict_email(data.get('email',''))
            elif self.path=='/predict-qr':
                raw=data.get('imageBase64',''); raw=raw.split(',',1)[-1]; raw_bytes=base64.b64decode(raw); fd,tmp=tempfile.mkstemp(suffix='.png'); os.close(fd)
                with open(tmp,'wb') as f:f.write(raw_bytes)
                img=cv2.imdecode(np.frombuffer(raw_bytes,np.uint8),cv2.IMREAD_COLOR)
                if img is None: raise ValueError('Invalid image data')
                cv2.imwrite(tmp,img); out=decode_qr(tmp)
            elif self.path=='/analyze-attachment':
                raw=data.get('fileBase64',''); raw=raw.split(',',1)[-1]; name=data.get('filename','attachment'); suffix=os.path.splitext(name)[1] or '.bin'; fd,tmp=tempfile.mkstemp(suffix=suffix); os.close(fd)
                with open(tmp,'wb') as f:f.write(base64.b64decode(raw))
                out=analyze_attachment(tmp,name)
            elif self.path=='/domain-intelligence': out=domain_intelligence(data.get('domain',''))
            elif self.path=='/analyze-screenshot':
                raw=data.get('imageBase64',''); raw=raw.split(',',1)[-1]; raw_bytes=base64.b64decode(raw); fd,tmp=tempfile.mkstemp(suffix='.png'); os.close(fd)
                with open(tmp,'wb') as f:f.write(raw_bytes)
                img=cv2.imdecode(np.frombuffer(raw_bytes,np.uint8),cv2.IMREAD_COLOR)
                if img is None: raise ValueError('Invalid image data')
                cv2.imwrite(tmp,img); out=analyze_screenshot(tmp)
            elif self.path=='/report': out=generate_report(data)
            else: send(self,404,{'error':'Not found'}); return
            send(self,200,out)
        except Exception as e: send(self,400,{'error':str(e)})
        finally:
            if tmp:
                try: os.remove(tmp)
                except OSError: pass
    def log_message(self,*args): pass
if __name__=='__main__': HTTPServer(('127.0.0.1',5100),Handler).serve_forever()
