import os, sys, time
for k in ("JWT_SECRET","APP_ENV"): os.environ.pop(k, None)
os.environ.update(MONGODB_URI="mongodb://127.0.0.1:27017", MONGODB_DATABASE="baseline_defsecret")
sys.path.insert(0, "/home/claude/work/baseline_run/backend"); os.chdir("/home/claude/work/baseline_run/backend")
import jwt
from fastapi.testclient import TestClient
from api.main import app
c = TestClient(app, raise_server_exceptions=False)
forged = jwt.encode({"sub":"99999","username":"nobody","role":"ADMIN","exp":int(time.time())+3600}, "dev-secret-change-me", algorithm="HS256")
print("DEFSECRET forged admin token (no such user) GET /api/users ->", c.get("/api/users", headers={"Authorization":"Bearer "+forged}).status_code)
