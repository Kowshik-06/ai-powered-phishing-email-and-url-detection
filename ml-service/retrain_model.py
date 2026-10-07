import os, json, joblib, pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix

BASE=os.path.dirname(os.path.abspath(__file__))
df=pd.read_csv(os.path.join(BASE,'dataset.csv'))
X=df.drop(columns=['target']); y=df['target']
X_train,X_test,y_train,y_test=train_test_split(X,y,test_size=.2,random_state=42,stratify=y)

rf=RandomForestClassifier(n_estimators=800,max_features='sqrt',min_samples_leaf=1,class_weight='balanced_subsample',random_state=42,n_jobs=-1)
hgb=HistGradientBoostingClassifier(max_iter=400,learning_rate=.04,max_leaf_nodes=15,l2_regularization=.5,random_state=42)
rf.fit(X_train,y_train); hgb.fit(X_train,y_train)

def score(model):
    pred=model.predict(X_test); prob=model.predict_proba(X_test)[:,1]
    return {'accuracy':round(accuracy_score(y_test,pred),4),'precision':round(precision_score(y_test,pred,zero_division=0),4),'recall':round(recall_score(y_test,pred,zero_division=0),4),'f1':round(f1_score(y_test,pred,zero_division=0),4),'roc_auc':round(roc_auc_score(y_test,prob),4),'confusion_matrix':confusion_matrix(y_test,pred).tolist()}

rf_metrics=score(rf); hgb_metrics=score(hgb)
joblib.dump(rf,os.path.join(BASE,'phishing_model.pkl'))
joblib.dump(hgb,os.path.join(BASE,'hgb_model.pkl'))
joblib.dump(list(X.columns),os.path.join(BASE,'feature_names.pkl'))
metrics={'randomForest':rf_metrics,'histGradientBoosting':hgb_metrics,'dataset':{'samples':len(df),'features':len(X.columns),'classCounts':y.value_counts().to_dict(),'duplicateRows':int(df.duplicated().sum())}}
joblib.dump(metrics,os.path.join(BASE,'metrics.pkl'))
joblib.dump(hgb_metrics,os.path.join(BASE,'hgb_metrics.pkl'))
joblib.dump(confusion_matrix(y_test,hgb.predict(X_test)),os.path.join(BASE,'confusion_matrix.pkl'))
with open(os.path.join(BASE,'training_report.json'),'w') as f: json.dump(metrics,f,indent=2)
print(json.dumps(metrics,indent=2))
