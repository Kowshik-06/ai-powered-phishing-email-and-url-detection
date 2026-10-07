import sys,json
from engine import predict_url
if __name__=='__main__':
    if len(sys.argv)<2: print(json.dumps({'error':'No URL provided'})); sys.exit(1)
    try: print(json.dumps(predict_url(sys.argv[1])))
    except Exception as e: print(json.dumps({'error':str(e)})); sys.exit(1)
