"""Train the optional email-text NLP baseline.
For research, replace starter_examples() with a licensed public dataset containing body,label.
"""
import os, joblib, json
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
BASE=os.path.dirname(__file__)

def starter_examples():
    phishing=[
      'urgent verify your account immediately click the secure login link',
      'your bank account has been suspended confirm your password now',
      'security alert unusual activity verify identity within 24 hours',
      'claim your refund by signing in and confirming your payment details',
      'your mailbox is full login now to prevent account closure',
      'reset your password immediately using the link below',
      'payment failed update your card information to avoid suspension',
      'administrator requires your credentials for verification',
      'you won a prize provide banking details to receive payment',
      'confirm your otp and account information urgently',
      'invoice overdue open the secure document and enter your credentials',
      'tax refund requires immediate identity verification',
      'your cloud account will be deleted unless you verify now',
      'wallet security check requires your recovery phrase',
      'click here to unlock your account after suspicious activity',
      'urgent payroll verification enter your employee password',
      'delivery failed confirm your address and payment card',
      'social account suspended appeal by logging in now',
      'microsoft security notice verify your credentials immediately',
      'bank fraud team needs your login and otp now'
    ]
    safe=[
      'weekly project meeting is scheduled for monday at ten am',
      'please review the attached agenda before the team meeting',
      'your monthly statement is available in the official mobile app',
      'thanks for submitting the assignment we will review it tomorrow',
      'the library will be closed on sunday for maintenance',
      'your order has shipped and the tracking number is in your account',
      'meeting notes from yesterday are attached for everyone',
      'please bring your identification card to the office tomorrow',
      'the university announced the examination timetable today',
      'your support ticket has been updated by our service team',
      'the software update is available through the official application',
      'we received your registration and will contact you with details',
      'team lunch is planned for friday afternoon',
      'your subscription receipt is available in your billing portal',
      'the report draft is ready for review by the project team',
      'please find the approved document attached to this message',
      'the workshop begins at nine and registration opens at eight',
      'your appointment has been confirmed for next week',
      'thanks for attending the cybersecurity awareness session',
      'the campus network maintenance is scheduled for tonight'
    ]
    return phishing+[1]*0, safe

def main():
    p,s=starter_examples(); X=p+s; y=[1]*len(p)+[0]*len(s)
    Xtr,Xte,ytr,yte=train_test_split(X,y,test_size=.25,random_state=42,stratify=y)
    pipe=Pipeline([('tfidf',TfidfVectorizer(ngram_range=(1,2),sublinear_tf=True,max_features=5000)),('clf',LogisticRegression(max_iter=1500,class_weight='balanced'))]);pipe.fit(Xtr,ytr); pred=pipe.predict(Xte)
    joblib.dump(pipe,os.path.join(BASE,'email_text_model.pkl')); metrics={'accuracy':accuracy_score(yte,pred),'precision':precision_score(yte,pred,zero_division=0),'recall':recall_score(yte,pred,zero_division=0),'f1':f1_score(yte,pred,zero_division=0),'dataset':'built-in starter templates; demo only'}
    json.dump(metrics,open(os.path.join(BASE,'email_text_metrics.json'),'w'),indent=2);print(json.dumps(metrics,indent=2))
if __name__=='__main__': main()
