import os, sys, json, base64, threading
os.environ.update(MONGODB_URI="mongodb://127.0.0.1:27017", MONGODB_DATABASE="baseline_race", JWT_SECRET="x")
sys.path.insert(0, "/home/claude/work/baseline_run/backend"); os.chdir("/home/claude/work/baseline_run/backend")
import pymongo; pymongo.MongoClient("mongodb://127.0.0.1:27017").drop_database("baseline_race")
from fastapi.testclient import TestClient
from api.main import app
from datetime import datetime, timezone
c = TestClient(app, raise_server_exceptions=False)
H=lambda r:{"Authorization":"Bearer "+r.json()["token"]}
reg=lambda u,role="USER_LEVEL_1": c.post("/api/auth/register",json={"username":u,"email":u+"@x.io","password":"Passw0rd!x","role":role})
b=reg("bob"); l2=reg("lead","USER_LEVEL_2"); desc=[0.01*i for i in range(128)]
c.post("/api/face/enroll",headers=H(b),json={"descriptor":desc})
c.post("/api/authorization/sessions/s1/refresh",headers=H(b),json={"device_id":"d1"})
c.post("/api/monitoring/start",headers=H(b),json={"device_id":"d1","session_id":"s1","face_confidence":0.9})
now=datetime.now(timezone.utc)
cid=dict(sender="bob",receiver="x",purpose="p",resource="r1",operation="encrypt",device_id="d1",session_id="s1",valid_from=now.isoformat(),valid_until=now.replace(year=now.year+1).isoformat())
iid=c.post("/api/intent",headers=H(b),json={"cid":cid}).json()["intent_id"]
c.post(f"/api/intent/{iid}/transition",headers=H(l2),json={"target_state":"approved","reason":"ok"})
key="ab"*32; res=[]
def go(): res.append(c.post("/api/encrypt",headers=H(b),json={"intent_id":iid,"cid":cid,"plaintext_base64":base64.b64encode(b"x").decode(),"quantum_key_hex":key,"face_descriptor":desc}).status_code)
ts=[threading.Thread(target=go) for _ in range(8)]; [t.start() for t in ts]; [t.join() for t in ts]
print("RACE one-shot intent, 8 concurrent encrypts, statuses:", sorted(res))
