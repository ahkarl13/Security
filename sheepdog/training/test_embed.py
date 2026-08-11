import urllib.request, json, time
t = time.time()
try:
    r = urllib.request.urlopen(urllib.request.Request(
        "http://localhost:11434/api/embed",
        data=json.dumps({"model": "qwen3-embedding:8b", "input": "hello world"}).encode(),
        headers={"Content-Type": "application/json"}), timeout=180)
    d = json.loads(r.read())
    v = d.get("embeddings") or d.get("embedding")
    dim = len(v[0] if isinstance(v[0], list) else v)
    print(f"EMBED-OK dim={dim} in {round(time.time()-t,1)}s", flush=True)
except Exception as e:
    print(f"EMBED-FAIL {type(e).__name__}: {str(e)[:200]}", flush=True)
