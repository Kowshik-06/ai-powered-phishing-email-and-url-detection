import json, os, joblib, numpy as np, pandas as pd, torch
from torch import nn
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, confusion_matrix
BASE=os.path.dirname(os.path.abspath(__file__))
df=pd.read_csv(os.path.join(BASE,'dataset.csv')); X=df.drop(columns=['target']).astype(np.float32); y=df['target'].astype(np.float32).values
Xtr,Xte,ytr,yte=train_test_split(X.values,y,test_size=.2,random_state=42,stratify=y)
scaler=StandardScaler(); Xtr=scaler.fit_transform(Xtr); Xte=scaler.transform(Xte)
joblib.dump(scaler,os.path.join(BASE,'deep_scaler.pkl')); joblib.dump(list(X.columns),os.path.join(BASE,'deep_feature_names.pkl'))
class MLP(nn.Module):
    def __init__(self,n):
        super().__init__(); self.net=nn.Sequential(nn.Linear(n,64),nn.ReLU(),nn.Dropout(.15),nn.Linear(64,32),nn.ReLU(),nn.Linear(32,1))
    def forward(self,x): return self.net(x).squeeze(1)
torch.manual_seed(42); model=MLP(Xtr.shape[1]); opt=torch.optim.Adam(model.parameters(),lr=.003,weight_decay=1e-4); loss_fn=nn.BCEWithLogitsLoss()
xt,yt=torch.tensor(Xtr),torch.tensor(ytr)
for _ in range(180):
    model.train(); opt.zero_grad(); loss=loss_fn(model(xt),yt); loss.backward(); opt.step()
model.eval()
with torch.no_grad(): probs=torch.sigmoid(model(torch.tensor(Xte))).numpy()
preds=(probs>=.5).astype(int)
metrics={'accuracy':round(accuracy_score(yte,preds),4),'precision':round(precision_score(yte,preds,zero_division=0),4),'recall':round(recall_score(yte,preds,zero_division=0),4),'f1':round(f1_score(yte,preds,zero_division=0),4),'roc_auc':round(roc_auc_score(yte,probs),4),'confusion_matrix':confusion_matrix(yte,preds).tolist(),'epochs_trained':180}
torch.save(model.state_dict(),os.path.join(BASE,'deep_model.pt'))
with open(os.path.join(BASE,'deep_metrics.json'),'w') as f: json.dump(metrics,f,indent=2)
print(json.dumps(metrics,indent=2))
