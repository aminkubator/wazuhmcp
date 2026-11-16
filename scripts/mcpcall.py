#!/usr/bin/env python3
"""Call WazuhMCP tools from the terminal, without an MCP client.

  export WAZUHMCP_TOKEN=<mcp token printed at startup>
  scripts/mcpcall.py health
  scripts/mcpcall.py alerts_summary '{"window":"1h","min_level":7}'
  scripts/mcpcall.py alerts_search '{"min_level":10,"limit":5}'
  scripts/mcpcall.py --list                      # tools available at this autonomy level

Options (before the tool name): --url http://127.0.0.1:8090/mcp   --max 4000 (output characters)
"""
import json, os, sys, urllib.request

args = sys.argv[1:]
url, maxc = os.environ.get("WAZUHMCP_URL", "http://127.0.0.1:8090/mcp"), 4000
while args and args[0].startswith("--") and args[0] != "--list":
    k = args.pop(0)
    v = args.pop(0)
    if k == "--url": url = v
    elif k == "--max": maxc = int(v)
tok = os.environ.get("WAZUHMCP_TOKEN")
if not tok or not args:
    sys.exit(__doc__)

def post(body, sid=None):
    h = {"Authorization": "Bearer " + tok, "Content-Type": "application/json",
         "Accept": "application/json, text/event-stream"}
    if sid: h["Mcp-Session-Id"] = sid
    try:
        r = urllib.request.urlopen(urllib.request.Request(url, json.dumps(body).encode(), h), timeout=60)
    except urllib.error.HTTPError as e:
        sys.exit(f"HTTP {e.code}: wrong token or wrong URL?")
    except OSError as e:
        sys.exit(f"cannot reach {url}: {e}")
    raw = r.read().decode()
    for line in raw.splitlines():
        if line.startswith("data:"): raw = line[5:].strip()
    return r.headers.get("Mcp-Session-Id"), (json.loads(raw) if raw.strip() else None)

sid, _ = post({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {
    "protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "mcpcall", "version": "1"}}})
post({"jsonrpc": "2.0", "method": "notifications/initialized"}, sid)

if args[0] == "--list":
    _, res = post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid)
    for t in sorted(res["result"]["tools"], key=lambda t: t["name"]):
        print(f'{t["name"]:20} {t["description"].split(". ")[0][:90]}')
    sys.exit()

name, call_args = args[0], json.loads(args[1]) if len(args) > 1 else {}
_, res = post({"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": name, "arguments": call_args}}, sid)
if "error" in res:
    sys.exit("error: " + res["error"]["message"])
r = res["result"]
out = r.get("structuredContent") or r["content"][0]["text"]
print(("ERROR: " if r.get("isError") else "") + (out if isinstance(out, str) else json.dumps(out, indent=1, ensure_ascii=False))[:maxc])
