import json, secrets, random
import httpx
from playwright.sync_api import sync_playwright
B="http://127.0.0.1:8000"
adm_pw=open("sec/admin_pw").read().strip()
def login(u,p):
    r=httpx.post(B+"/api/auth/login",json={"username":u,"password":p}); r.raise_for_status(); return r.json()
name="pg"+secrets.token_hex(3); pw="Pg-"+secrets.token_urlsafe(12)
r=httpx.post(B+"/api/auth/register",json={"username":name,"email":name+"@example.test","password":pw}); u=r.json()
H={"Authorization":"Bearer "+u["token"]}
dev=httpx.post(B+"/api/authorization/devices",headers=H).json()["device_id"]
sess=httpx.post(B+"/api/authorization/sessions",headers=H,json={"device_id":dev}).json()["session_id"]
adm=login("e2eadmin",adm_pw); AH={"Authorization":"Bearer "+adm["token"]}
face=[round(random.uniform(-1,1),4) for _ in range(128)]
httpx.post(B+"/api/face/enroll",headers=H,json={"descriptor":face,"password":pw})
httpx.post(B+"/api/key-sessions",headers=H,json={"n_qubits":1024},timeout=60)
httpx.put(B+"/api/evidence/cases/CASE-424242",headers=AH,json={"title":"UI smoke case","classification_cap":"RESTRICTED","allowed_resources":["vault:ui-demo"],"assigned_user_ids":[u["user_id"]],"status":"OPEN"})
errs=[]
def run(role_label, tok, user, pages, dev, sess):
    with sync_playwright() as p:
        b=p.chromium.launch(args=["--use-fake-device-for-media-stream","--use-fake-ui-for-media-stream"])
        ctx=b.new_context(viewport={"width":1400,"height":950})
        pg=ctx.new_page()
        pg.on("pageerror",lambda e:errs.append((role_label,"pageerror",str(e))))
        pg.on("console",lambda m:errs.append((role_label,m.text)) if m.type=="error" and "ERR_TUNNEL" not in m.text else None)
        pg.goto("http://127.0.0.1:5173/")
        pg.evaluate("""([t,u,s,d])=>{localStorage.setItem('ibqc_token',t);localStorage.setItem('ibqc_user',JSON.stringify(u));localStorage.setItem('ibqc_session_id',s);localStorage.setItem('ibqc_device_id_'+u.userId,d);sessionStorage.setItem('ibqc_security_access_consent','allow')}""",[tok,{"userId":user["user_id"],"username":user["username"],"role":user["role"]},sess,dev])
        pg.reload(); pg.wait_for_timeout(2000)
        print(role_label,'landing buttons',pg.locator('button').all_inner_texts()[:6])
        for t in ('Open Dashboard','Dashboard','Go to Dashboard','Open dashboard'):
            if pg.get_by_role('button',name=t).count(): pg.get_by_role('button',name=t).first.click(); break
        pg.wait_for_timeout(2500)
        for label in pages:
            loc=pg.get_by_text(label,exact=True).first
            if loc.count()==0: print(role_label,"NAV MISSING",label); continue
            loc.evaluate('e=>e.closest("button").click()'); pg.wait_for_timeout(1500)
            fn=f"ui_{role_label}_{label.replace(' ','_')}.png"; pg.screenshot(path=fn)
            txt=pg.inner_text("body")
            if label=="Admin Dashboard":
                for tab in ("Intent Approval","Evidence Cases"):
                    t=pg.get_by_text(tab,exact=True).first
                    if t.count(): t.click(); pg.wait_for_timeout(1500); pg.screenshot(path="ui_admin_"+tab.replace(" ","_")+".png"); print("admin tab",tab,len(pg.inner_text("body")))
            print(role_label,label,"OK len",len(txt), "| error banner" if "something went wrong" in txt.lower() else "")
        b.close()
run("user",u["token"],u,["Overview","Create Intent","Intent History","Quantum Lab","Encryption","Decryption","Audit","Identity"],dev,sess)
ad=httpx.post(B+"/api/authorization/devices",headers=AH).json()["device_id"]
asess=httpx.post(B+"/api/authorization/sessions",headers=AH,json={"device_id":ad}).json()["session_id"]
run("admin",adm["token"],adm,["Admin Dashboard","Audit"],ad,asess)
print("ERRORS",errs[:15])
