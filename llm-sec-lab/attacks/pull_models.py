import json, time, urllib.request
import os

BASE = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
MODELS = ["llama3.2:3b", "qwen3:4b"]

def pull(name):
    data = json.dumps({"model": name, "stream": False}).encode()
    req = urllib.request.Request(BASE + "/api/pull", data=data,
                                 headers={"Content-Type": "application/json"})
    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=1200) as r:
            resp = json.loads(r.read().decode())
        print(f"{name}: {resp.get('status', resp)} ({time.time()-t0:.0f}s)", flush=True)
    except Exception as e:
        print(f"{name}: ERROR {e}", flush=True)

for m in MODELS:
    print(f"pulling {m} ...", flush=True)
    pull(m)
print("done", flush=True)
