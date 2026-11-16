import json, secrets, sys
from playwright.sync_api import sync_playwright
name = "ui" + secrets.token_hex(3); pw = "Ui-" + secrets.token_urlsafe(12)
errs, reqs = [], []
with sync_playwright() as p:
    b = p.chromium.launch(args=["--use-fake-device-for-media-stream", "--use-fake-ui-for-media-stream"])
    pg = b.new_page(viewport={"width": 1300, "height": 900})
    pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.on("console", lambda m: errs.append(m.text) if m.type == "error" else None)
    pg.on("request", lambda r: reqs.append(f"{r.method} {r.url.split('5173')[-1]}") if "/api/" in r.url else None)
    pg.goto("http://127.0.0.1:5173/")
    pg.wait_for_timeout(1500)
    pg.screenshot(path="s1_landing.png")
    print([t for t in pg.locator("button").all_inner_texts()][:10])
    for label in ("Create account", "Register", "Sign up", "Get started", "Get Started"):
        if pg.get_by_role("button", name=label).count():
            pg.get_by_role("button", name=label).first.click(); break
    pg.wait_for_timeout(800)
    pg.screenshot(path="s2_register.png")
    print("inputs:", pg.locator("input").count())
    ins = pg.locator("input")
    ins.nth(0).fill(name); ins.nth(1).fill(f"{name}@example.test"); ins.nth(2).fill(pw)
    pg.locator("button[type=submit]").first.click()
    pg.wait_for_timeout(3500)
    pg.screenshot(path="s3_after_register.png")
    print(pg.inner_text("body")[:600])
    print("API calls:", reqs)
    print("localStorage session/device:", pg.evaluate("[localStorage.getItem('ibqc_session_id'), Object.keys(localStorage).filter(k=>k.startsWith('ibqc_device'))]"))
    print("ERRORS:", errs[:10])
    b.close()
