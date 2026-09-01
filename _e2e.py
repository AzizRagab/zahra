"""End-to-end: server up, WS live events, campaign create, risk enrichment."""
import json
import subprocess
import sys
import time
import urllib.request

ROOT = r"c:\Users\Admin\Desktop\zahra"

# which ws library?
HAVE_WEBSOCKETS = False
try:
    import websockets  # noqa: F401
    HAVE_WEBSOCKETS = True
except Exception:
    pass
HAVE_WS_CLIENT = False
try:
    import websocket  # noqa: F401
    HAVE_WS_CLIENT = True
except Exception:
    pass
print("WS_LIB: websockets=%s websocket_client=%s" % (HAVE_WEBSOCKETS, HAVE_WS_CLIENT))

proc = subprocess.Popen(
    [sys.executable, "main.py", "serve", "--port", "8082"],
    cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
)
try:
    base = "http://127.0.0.1:8082"
    up = False
    for _ in range(20):
        try:
            with urllib.request.urlopen(base + "/health", timeout=3) as r:
                assert r.status == 200
                up = True
                break
        except Exception:
            time.sleep(2)
    assert up, "server did not start"

    # 1) risk enrichment on a synthetic finding via the scoring endpoint
    req = urllib.request.Request(
        base + "/api/risk/score",
        data=json.dumps({"severity": "critical", "port": 443,
                         "description": "OpenSSH 8.2 CVE-2020-15778", "target": "127.0.0.1"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        risk = json.loads(r.read().decode())
    print("RISK_SCORE=%s LEVEL=%s COLOR=%s" % (
        risk.get("risk_score"), risk.get("risk_level"), risk.get("risk_color")))

    # 2) findings endpoint returns list (may be empty)
    with urllib.request.urlopen(base + "/memory/findings", timeout=5) as r:
        findings = json.loads(r.read().decode())
    print("FINDINGS_ENDPOINT=%s count=%d" % (type(findings).__name__, len(findings)))

    # 3) create a campaign (triggers orchestrator + likely WS broadcast)
    req = urllib.request.Request(
        base + "/api/campaign",
        data=json.dumps({"command": "recon 127.0.0.1"}).encode(),
        headers={"Content-Type": "application/json"}, method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as r:
        camp = json.loads(r.read().decode())
    print("CAMPAIGN_CREATED id=%s status=%s" % (camp.get("id"), camp.get("status")))

    # 4) WS live events — connect and collect frames for ~6s
    ws_received = []
    if HAVE_WEBSOCKETS or HAVE_WS_CLIENT:
        import asyncio
        async def ws_collect():
            frames = []
            try:
                import websockets as wslib
                async with wslib.connect("ws://127.0.0.1:8082/ws/attack") as ws:
                    try:
                        frames.append(await asyncio.wait_for(ws.recv(), timeout=3))
                    except Exception:
                        pass
                    # create a campaign while connected to provoke a broadcast
                    req2 = urllib.request.Request(
                        base + "/api/campaign",
                        data=json.dumps({"command": "scan 127.0.0.1"}).encode(),
                        headers={"Content-Type": "application/json"}, method="POST")
                    try:
                        urllib.request.urlopen(req2, timeout=5).read()
                    except Exception:
                        pass
                    deadline = time.time() + 6
                    while time.time() < deadline:
                        try:
                            frames.append(await asyncio.wait_for(ws.recv(), timeout=1))
                        except Exception:
                            break
            except Exception as exc:
                print("WS_ERR %r" % exc)
            return frames
        ws_received = asyncio.run(ws_collect())
        print("WS_RECEIVED=%d frames" % len(ws_received))
        for fr in ws_received[:6]:
            print("  WS:", str(fr)[:140])
    else:
        print("WS_RECEIVED=SKIP (no ws lib)")
    print("ALL_E2E_DONE")
finally:
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except Exception:
        proc.kill()