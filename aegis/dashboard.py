"""Minimal role-based operator dashboard (stdlib only).

The dashboard demonstrates the FYP-I use cases: task registration, action
submission, decision explanation, audit review and on-demand evaluation.
No third-party web framework is required to run the prototype.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

from .audit import AuditLogger
from .config import Config
from .evaluation import format_summary, run_evaluation
from .gateway import AegisGateway

INDEX_HTML = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AEGIS FYP-I Console</title>
<style>
 body{font-family:Arial,sans-serif;margin:0;background:#f4f6fa;color:#1c2b3a}
 header{background:#123a63;color:white;padding:18px 28px}
 header h1{margin:0;font-size:22px} header p{margin:4px 0 0;color:#c9d9e8;font-size:13px}
 .wrap{max-width:1100px;margin:22px auto;padding:0 18px}
 .grid{display:grid;grid-template-columns:1fr 1fr;gap:18px}
 .card{background:white;border:1px solid #d8e0ea;border-radius:8px;padding:18px;margin-bottom:18px}
 h2{margin:0 0 12px;font-size:16px;color:#123a63}
 label{display:block;font-size:12px;font-weight:bold;margin:8px 0 4px}
 input,select,textarea,button{font-family:inherit;font-size:14px;padding:8px;border:1px solid #b9c6d4;border-radius:5px}
 input,select,textarea{width:100%;box-sizing:border-box} textarea{min-height:70px}
 button{background:#123a63;color:white;border:none;cursor:pointer;margin-top:12px}
 button:hover{background:#1d5590}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{border-bottom:1px solid #e3e9f0;padding:7px;text-align:left;vertical-align:top}
 th{background:#eef3f9;color:#234}
 .allow{color:#137333;font-weight:bold}.deny{color:#b3261e;font-weight:bold}
 .muted{color:#66788a;font-size:12px} pre{white-space:pre-wrap;font-size:12px;background:#f7f9fc;padding:10px;border-radius:5px}
 @media(max-width:800px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<header><h1>AEGIS - Runtime Authorization Console</h1>
<p>FYP-I core prototype | intent-aware, capability-scoped, policy + risk decisions</p></header>
<div class="wrap">
 <div class="grid">
  <div class="card">
   <h2>1. Register a task</h2>
   <label>Task description</label>
   <textarea id="taskDesc">Fix the authentication bug and run the tests</textarea>
   <label>Operator</label><input id="owner" value="operator">
   <button onclick="registerTask()">Register task</button>
   <p id="taskInfo" class="muted">No task registered yet.</p>
  </div>
  <div class="card">
   <h2>2. Submit an agent action</h2>
   <label>Task ID</label><input id="taskId" placeholder="TASK-...">
   <label>Operation</label>
   <select id="operation"><option>READ</option><option>WRITE</option><option>EXECUTE</option>
    <option>DATABASE</option><option>NETWORK</option><option>DELETE</option></select>
   <label>Resource</label><input id="resource" value="src/auth/login.py">
   <label>Source</label><select id="source"><option>agent</option><option>untrusted_content</option></select>
   <label>Parameters (JSON, optional)</label><input id="params" value='{}'>
   <button onclick="submitAction()">Authorize &amp; execute</button>
  </div>
 </div>
 <div class="card">
  <h2>Decision history</h2>
  <table><thead><tr><th>Time</th><th>Action</th><th>Decision</th><th>Rule</th><th>Risk</th><th>Explanation</th></tr></thead>
  <tbody id="history"><tr><td colspan="6" class="muted">No decisions yet.</td></tr></tbody></table>
 </div>
 <div class="grid">
  <div class="card"><h2>Audit &amp; provenance</h2><p id="auditInfo" class="muted">-</p>
   <button onclick="loadState()">Refresh state</button></div>
  <div class="card"><h2>Evaluation</h2><p class="muted">Runs the 12 controlled scenarios and compares AEGIS with both baselines.</p>
   <button onclick="runEvaluation()">Run FYP-I evaluation</button><pre id="evalOut">Not run yet.</pre></div>
 </div>
</div>
<script>
let taskId = '';
async function post(path, body){
  const r = await fetch(path,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body||{})});
  return r.json();
}
async function registerTask(){
  const data = await post('/api/tasks',{description:document.getElementById('taskDesc').value,owner:document.getElementById('owner').value});
  if(data.error){alert(data.error);return;}
  taskId = data.task.id; document.getElementById('taskId').value = taskId;
  document.getElementById('taskInfo').textContent = data.task.id + ' | intent: ' + (data.task.intent.expected_operations.join(', '));
  await loadState();
}
async function submitAction(){
  let params;
  try {
    params = JSON.parse(document.getElementById('params').value||'{}');
    if(params===null || typeof params!=='object' || Array.isArray(params)){
      throw new Error('Parameters must be a JSON object');
    }
  } catch(err) {
    alert('Invalid parameters JSON: '+err.message);
    return;
  }
  const body={task_id:document.getElementById('taskId').value || taskId,
    operation:document.getElementById('operation').value,
    resource:document.getElementById('resource').value,
    source:document.getElementById('source').value,
    params:params};
  const data = await post('/api/actions',body);
  if(data.error){alert(data.error);return;}
  const d = data.decision;
  const row=document.createElement('tr');
  row.innerHTML='<td>'+new Date().toLocaleTimeString()+'</td><td>'+d.risk.sensitivity_label+' / '+d.risk.sensitivity+'</td>'+
    '<td class="'+d.outcome.toLowerCase()+'">'+d.outcome+'</td><td>'+d.policy.rule_id+'</td><td>'+d.risk.score+'</td><td>'+d.explanation+'</td>';
  document.getElementById('history').prepend(row);
  await loadState();
}
async function loadState(){
  const s = await (await fetch('/api/state')).json();
  document.getElementById('auditInfo').textContent = s.audit_events+' audit events | hash chain '+(s.chain_valid?'valid':'BROKEN')+' | tasks: '+s.tasks;
}
async function runEvaluation(){
  document.getElementById('evalOut').textContent='Running...';
  const data = await post('/api/evaluate',{});
  document.getElementById('evalOut').textContent = data.summary || data.error;
}
loadState();
</script>
</body></html>"""


# Only one evaluation should write the shared results file at a time.
_EVALUATION_LOCK = threading.Lock()


class AegisHandler(BaseHTTPRequestHandler):
    """HTTP handler backed by a single shared gateway instance."""

    gateway: AegisGateway
    config: Config

    def log_message(self, fmt: str, *args: Any) -> None:  # pragma: no cover
        pass

    def _send(self, status: int, payload: Any, content_type: str = "application/json") -> None:
        if content_type == "application/json":
            body = json.dumps(payload, default=str).encode("utf-8")
        else:
            body = str(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _json_body(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except json.JSONDecodeError:
            return {}

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path in ("/", "/index.html"):
            self._send(200, INDEX_HTML, "text/html")
            return
        if parsed.path == "/api/state":
            chain, broken = self.gateway.audit.verify_chain()
            self._send(200, {
                "tasks": len(self.gateway.tasks),
                "audit_events": self.gateway.audit.count(),
                "chain_valid": chain,
                "broken_events": broken,
            })
            return
        if parsed.path == "/api/audit":
            query = parse_qs(parsed.query)
            task_id = query.get("task_id", [None])[0]
            self._send(200, {"events": self.gateway.audit.events(task_id=task_id)})
            return
        self._send(404, {"error": "Not found"})

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        body = self._json_body()
        if parsed.path == "/api/tasks":
            try:
                task = self.gateway.register_task(
                    body.get("description", ""), body.get("owner", "operator")
                )
                self._send(200, {"task": task.to_dict()})
            except Exception as exc:  # noqa: BLE001
                self._send(400, {"error": str(exc)})
            return
        if parsed.path == "/api/actions":
            try:
                decision = self.gateway.handle(
                    body["task_id"],
                    body.get("tool", "tool"),
                    body["operation"],
                    body["resource"],
                    params=body.get("params") or {},
                    source=body.get("source", "agent"),
                    execute=bool(body.get("execute", True)),
                )
                self._send(200, {"decision": decision.to_dict()})
            except Exception as exc:  # noqa: BLE001
                self._send(400, {"error": str(exc)})
            return
        if parsed.path == "/api/evaluate":
            with _EVALUATION_LOCK:
                try:
                    results = run_evaluation(config=self.config, save=True)
                    self._send(200, {"summary": format_summary(results)})
                except Exception as exc:  # noqa: BLE001
                    self._send(500, {"error": str(exc)})
            return
        self._send(404, {"error": "Not found"})


def serve(config: Optional[Config] = None, host: str = "127.0.0.1", port: int = 8766) -> None:
    """Start the dashboard web server (blocking)."""
    config = config or Config()
    handler = type("BoundAegisHandler", (AegisHandler,), {
        "gateway": AegisGateway(config=config),
        "config": config,
    })
    server = ThreadingHTTPServer((host, port), handler)
    print(f"AEGIS dashboard running at http://{host}:{port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        handler.gateway.audit.close()
        server.server_close()
