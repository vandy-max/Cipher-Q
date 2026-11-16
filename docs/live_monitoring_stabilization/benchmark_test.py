"""Benchmark (not part of the project): DB ops and latency per heartbeat. Copied into a tests dir temporarily."""
import json, os, time, collections
import mongomock.collection as mc
import pytest
from .flow import Flow, jitter

READ = ["find", "find_one", "count_documents", "aggregate", "distinct"]
WRITE = ["insert_one", "insert_many", "update_one", "update_many", "replace_one", "delete_one", "delete_many", "find_one_and_update", "find_one_and_replace", "bulk_write"]

def test_bench(client, user, admin, monkeypatch):
    cnt = collections.Counter()
    def wrap(name, kind):
        orig = getattr(mc.Collection, name)
        def w(self, *a, **k):
            cnt[(kind, self.name)] += 1
            return orig(self, *a, **k)
        monkeypatch.setattr(mc.Collection, name, w)
    for n in READ: wrap(n, "read")
    for n in WRITE: wrap(n, "write")
    f = Flow(client, user, admin).ready()
    N = int(os.environ.get("BENCH_N", "40"))
    nonce = f.mon["heartbeat_nonce"]; mid = f.mon["monitoring_session_id"]
    cnt.clear(); lat = []
    for _ in range(N):
        t = time.perf_counter()
        r = f.user.post("/api/monitoring/heartbeat", {"monitoring_session_id": mid, "prev_nonce": nonce, "probe_descriptor": jitter()})
        lat.append(time.perf_counter() - t)
        assert r.status_code == 200, r.text
        nonce = r.json()["heartbeat_nonce"]
    ev = [e for e in f.user.get(f"/api/monitoring/{mid}/events").json()] if hasattr(f.user, "get") else []
    reads = sum(v for (k, _), v in cnt.items() if k == "read"); writes = sum(v for (k, _), v in cnt.items() if k == "write")
    mon_w = sum(v for (k, c), v in cnt.items() if k == "write" and c.startswith("monitoring"))
    out = {"heartbeats": N, "reads_per_hb": reads / N, "writes_per_hb": writes / N, "monitoring_collection_writes_per_hb": mon_w / N,
           "mean_ms": 1000 * sum(lat) / N, "p95_ms": 1000 * sorted(lat)[int(.95 * N) - 1],
           "writes_by_collection": {c: v / N for (k, c), v in sorted(cnt.items()) if k == "write"},
           "reads_by_collection": {c: v / N for (k, c), v in sorted(cnt.items()) if k == "read"},
           "events_after": len(ev) if isinstance(ev, list) else None}
    open(os.environ["BENCH_OUT"], "w").write(json.dumps(out, indent=1))
