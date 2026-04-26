import os
import sys
import json
import time
import asyncio
import threading
from datetime import datetime
from typing import Any, Dict, List, Optional

import logging
from fastapi import FastAPI, WebSocket, WebSocketDisconnect, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel

# Ensure the project root is importable from backend/main.py
_ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _ROOT_DIR)

# Load .env from the repo root before importing modules that depend on it.
_ENV_PATH = os.path.join(_ROOT_DIR, ".env")

def _load_dotenv(path):
    if not os.path.isfile(path):
        return
    try:
        from dotenv import load_dotenv
        load_dotenv(path)
    except ImportError:
        try:
            with open(path, encoding="utf-8") as f:
                for raw in f:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    key, value = line.split("=", 1)
                    key = key.strip()
                    value = value.strip().strip('"').strip("'")
                    if key and value and key not in os.environ:
                        os.environ[key] = value
        except Exception:
            pass

_load_dotenv(_ENV_PATH)

import vulnscanner

logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(message)s')
logger = logging.getLogger('vulnscan_backend')

app = FastAPI(title="VulnScan API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

API_STATUS_TTL = 20
api_status_cache = {
    "status": {
        "nvd_api": False,
        "exploit_db": False,
        "gemini_ai": False,
    },
    "last_checked": 0,
}


class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = threading.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        with self._lock:
            self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        with self._lock:
            conns = list(self.active_connections)
        for conn in conns:
            try:
                await conn.send_text(message)
            except Exception:
                pass

    def broadcast_from_thread(self, message: str, loop):
        try:
            future = asyncio.run_coroutine_threadsafe(self.broadcast(message), loop)
            future.result(timeout=2)
        except Exception:
            pass

manager = ConnectionManager()


def _make_serializable(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _make_serializable(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_make_serializable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _current_api_key() -> Optional[str]:
    key = os.getenv("NVD_API_KEY", "").strip()
    return key if len(key) > 5 else None


def _check_nvd_api_key() -> bool:
    api_key = _current_api_key()
    if not api_key:
        return False

    try:
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
    except ImportError:
        return False

    session = requests.Session()
    retry = Retry(
        total=2,
        backoff_factor=0.8,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET"],
        raise_on_status=False,
    )
    session.mount("https://", HTTPAdapter(max_retries=retry))
    session.mount("http://", HTTPAdapter(max_retries=retry))

    try:
        response = session.get(
            "https://services.nvd.nist.gov/rest/json/cves/2.0",
            headers={"apiKey": api_key},
            params={"keywordSearch": "vulnscan health check", "resultsPerPage": 1},
            timeout=3,
        )
        return response.status_code == 200
    except Exception:
        return False


async def _get_api_status() -> Dict[str, bool]:
    now = time.monotonic()
    if now - api_status_cache["last_checked"] < API_STATUS_TTL:
        return api_status_cache["status"].copy()

    def compute_status():
        status = {
            "nvd_api": _check_nvd_api_key(),
            "exploit_db": False,
            "gemini_ai": False,
        }
        exploit_path = os.getenv("EXPLOIT_DB_PATH", "exploitdb/files_exploits.csv")
        full_path = os.path.join(_ROOT_DIR, exploit_path) if not os.path.isabs(exploit_path) else exploit_path
        status["exploit_db"] = os.path.isfile(full_path)

        gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
        if gemini_key and len(gemini_key) > 5:
            try:
                import importlib.util
                gemini_installed = bool(importlib.util.find_spec("google.genai") or importlib.util.find_spec("google.generativeai"))
            except Exception:
                gemini_installed = False
            status["gemini_ai"] = gemini_installed
        return status

    status = await asyncio.to_thread(compute_status)
    api_status_cache["status"] = status
    api_status_cache["last_checked"] = now
    return status


scan_state = {
    "status": "idle",
    "stop_requested": False,
    "stop_event": threading.Event(),
    "task": None,
    "last_error": None,
    "lock": threading.Lock(),
}


def _is_scan_running() -> bool:
    task = scan_state.get("task")
    if task is None:
        return False
    return not task.done()


def _request_stop() -> bool:
    with scan_state["lock"]:
        if scan_state["stop_requested"]:
            return False
        scan_state["stop_requested"] = True
        scan_state["stop_event"].set()
        if scan_state["status"] == "running":
            scan_state["status"] = "stopping"
        return True


def _clear_scan_state():
    with scan_state["lock"]:
        scan_state["status"] = "idle"
        scan_state["stop_requested"] = False
        scan_state["stop_event"].clear()
        scan_state["task"] = None
        scan_state["last_error"] = None


def _serialize_scan_result(data: Any) -> Any:
    return _make_serializable(data)


class WebSocketWriter:
    def __init__(self, manager, loop, original_stdout):
        self.manager = manager
        self.loop = loop
        self.original = original_stdout
        self._buffer = ""

    def write(self, text: str):
        if self.original:
            try:
                self.original.write(text)
            except Exception:
                pass
        self._buffer += text
        while "\n" in self._buffer:
            line, self._buffer = self._buffer.split("\n", 1)
            clean = line.strip()
            if clean:
                self.manager.broadcast_from_thread(json.dumps({"type": "log", "message": clean}), self.loop)

    def flush(self):
        if self.original:
            try:
                self.original.flush()
            except Exception:
                pass
        if self._buffer.strip():
            clean = self._buffer.strip()
            if clean:
                self.manager.broadcast_from_thread(json.dumps({"type": "log", "message": clean}), self.loop)
            self._buffer = ""


class ScanRequest(BaseModel):
    target: str
    ports: str = "common"
    num_cves: int = 5
    ai_enabled: bool = True
    monitor_duration: int = 0
    pcap_path: Optional[str] = None
    output_mode: str = "text"


@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


@app.get("/", response_class=HTMLResponse)
async def root():
    dist_path = os.path.join(_ROOT_DIR, "frontend", "dist")
    if os.path.isdir(dist_path):
        return FileResponse(os.path.join(dist_path, "index.html"))
    return HTMLResponse("<h1>VulnScan Backend is running.</h1><p>Run the frontend with npm run dev in frontend/.</p>")


@app.get("/status")
async def get_status():
    return await _get_api_status()


@app.get("/scan-status")
async def get_scan_status():
    if _is_scan_running() and scan_state["status"] == "stopping":
        return {"status": "stopping"}
    if _is_scan_running():
        return {"status": "running"}
    if scan_state["status"] == "stopping":
        return {"status": "stopping"}
    if scan_state["status"] == "completed":
        return {"status": "completed"}
    if scan_state["status"] == "error":
        return {"status": "error", "message": scan_state.get("last_error")}
    return {"status": "idle"}


@app.post("/start-scan")
async def start_scan(request: ScanRequest):
    if _is_scan_running():
        raise HTTPException(status_code=409, detail="A scan is already running.")
    _clear_scan_state()
    scan_state["status"] = "running"
    scan_state["stop_event"] = threading.Event()
    scan_state["stop_requested"] = False

    loop = asyncio.get_running_loop()

    def _broadcast_step(event):
        manager.broadcast_from_thread(json.dumps({"type": "step", "payload": event}), loop)

    def _scan_thread():
        results = None
        try:
            logger.info(f"Scan started at {datetime.utcnow().isoformat()}")
            results = vulnscanner.run_scan(
                request.target,
                request.ports,
                request.num_cves,
                request.output_mode,
                pcap_path=request.pcap_path,
                ai_enabled=request.ai_enabled,
                monitor_duration=request.monitor_duration,
                stop_requested=scan_state["stop_event"].is_set,
                pretty_output=False,
                step_callback=_broadcast_step,
            )
            if scan_state["stop_event"].is_set():
                scan_state["status"] = "stopped"
            else:
                scan_state["status"] = "completed"
        except Exception as exc:
            scan_state["status"] = "error"
            scan_state["last_error"] = str(exc)
            logger.exception("Scan failed")
        finally:
            if results is not None:
                payload = _serialize_scan_result(results)
                response_payload = {
                    "status": "success",
                    "scan_results": payload,
                    "ai_analysis": payload.get("ai_analysis") or payload.get("ai_analysis_items", []),
                    "ai_analysis_items": payload.get("ai_analysis_items", []),
                    "ai_mitigation": payload.get("ai_mitigation", {"summary": "", "steps": []}),
                }
                manager.broadcast_from_thread(json.dumps({"type": "results", "payload": response_payload}), loop)
            else:
                manager.broadcast_from_thread(json.dumps({"type": "results", "payload": {"status": "error", "message": "Scan failed.", "target": request.target}}), loop)
            _clear_scan_state()

    scan_state["task"] = asyncio.create_task(asyncio.to_thread(_scan_thread))
    return {"status": "running", "message": "Scan started."}


@app.post("/stop-scan")
async def stop_scan():
    if not _is_scan_running() and scan_state["status"] != "running":
        return {"status": "idle", "message": "No scan is currently running."}
    if _request_stop():
        return {"status": "stopping", "message": "Stop requested."}
    return {"status": scan_state["status"], "message": "Stop already requested."}
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)
