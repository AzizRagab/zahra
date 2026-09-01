import json
import subprocess
import sys
import time
import urllib.request

ROOT = r"c:\Users\Admin\Desktop\zahra"
proc = subprocess.Popen([sys.executable, "main.py", "serve", "--port", "8083"],
                        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
try:
    base = "http://127.0.0.1:8083"
    for _ in range(20):
        try:
            urllib.request.urlopen(base + "/health", timeout=3).read()
            break
        except Exception:
            time.sleep(2)
    with urllib.request.urlopen(base + "/memory/findings", timeout=8) as r:
        data = json.loads(r.read().decode())
    print("count=%d" % len(data))
    enriched = [f for f in data if "risk_score" in f]
    print("ENRICHED_WITH_RISK=%d" % len(enriched))
    if enriched:
        s = enriched[0]
        print("SAMPLE keys:", "risk_score=%s risk_level=%s risk_color=%s cve=%s sev=%s" % (
            s.get("risk_score"), s.get("risk_level"), s.get("risk_color"),
            s.get("cve"), s.get("severity")))
    # unit check enrich_dict direct
    from core.risk_engine import get_risk_engine
    out = get_risk_engine().enrich_dict({
        "severity": "critical", "description": "RCE CVE-2024-0001 on port 443",
        "port": 443, "target": "10.0.0.9", "finding_type": "vuln"})
    print("ENRICH_DIRECT: score=%s level=%s color=%s" % (
        out.get("risk_score"), out.get("risk_level"), out.get("risk_color")))
    print("FINAL_OK")
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()