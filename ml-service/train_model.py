import os, json, joblib, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

BASE=os.path.dirname(os.path.abspath(__file__))
df=pd.read_csv(os.path.join(BASE,'dataset.csv'))
X=df.drop(columns=['target']); y=df['target']
X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)
model=RandomForestClassifier(n_estimators=300,random_state=42,class_weight='balanced',n_jobs=-1)
model.fit(X_train,y_train)
preds=model.predict(X_test); probs=model.predict_proba(X_test)[:,1]
metrics={'accuracy':round(accuracy_score(y_test,preds),4),'precision':round(precision_score(y_test,preds,zero_division=0),4),'recall':round(recall_score(y_test,preds,zero_division=0),4),'f1':round(f1_score(y_test,preds,zero_division=0),4),'roc_auc':round(roc_auc_score(y_test,probs),4),'confusion_matrix':confusion_matrix(y_test,preds).tolist()}
joblib.dump(model,os.path.join(BASE,'phishing_model.pkl')); joblib.dump(list(X.columns),os.path.join(BASE,'feature_names.pkl')); joblib.dump(metrics,os.path.join(BASE,'metrics.pkl')); joblib.dump(confusion_matrix(y_test,preds),os.path.join(BASE,'confusion_matrix.pkl'))
print(json.dumps(metrics,indent=2))
