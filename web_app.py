"""Browser demo API for Secure AI Gateway. Also serves benchmark + admin pages."""
import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from secure_ai.config import Settings
from secure_ai.demo_world import build_world
from secure_ai.llm import MockLLM
from secure_ai.llm_groq import GroqLLM
from benchmarks.security.admin import get_admin_stats


BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
INDEX_FILE = STATIC_DIR / "index.html"
BENCHMARKS_DIR = BASE_DIR / "benchmarks" / "security" / "runs"

DEMO_USERS = {"alice", "bob", "admin"}

app = FastAPI(title="Secure AI Gateway", version="1.1.0")

# Choose LLM
_llm = None
if os.getenv("GROQ_API_KEY"):
    try:
        _llm = GroqLLM()
        print("[web_app] Using Groq LLM")
    except Exception as e:
        print(f"[web_app] Groq failed, using mock: {e}")
if _llm is None:
    _llm = MockLLM()
    print("[web_app] Using Mock LLM")

world = build_world(Settings(render_html=False), llm=_llm)
gateway = world.gateway

if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


class ChatRequest(BaseModel):
    user: str = Field(min_length=1, max_length=40)
    message: str = Field(min_length=1, max_length=4000)


def get_result_field(result, *names, default=None):
    for name in names:
        if isinstance(result, dict) and name in result:
            return result[name]
        if hasattr(result, name):
            return getattr(result, name)
    return default


def json_safe(value):
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [json_safe(v) for v in value]
    return str(value)


def _latest_benchmark_run() -> Path | None:
    if not BENCHMARKS_DIR.is_dir():
        return None
    dirs = sorted(
        (p for p in BENCHMARKS_DIR.iterdir() if p.is_dir() and (p / "report.json").is_file()),
        key=lambda p: p.name, reverse=True,
    )
    return dirs[0] if dirs else None


def _all_benchmark_runs() -> list[str]:
    if not BENCHMARKS_DIR.is_dir():
        return []
    return sorted(
        [p.name for p in BENCHMARKS_DIR.iterdir() if p.is_dir() and (p / "report.json").is_file()],
        reverse=True,
    )


@app.get("/")
def home():
    if not INDEX_FILE.is_file():
        raise HTTPException(status_code=500, detail="static/index.html is missing.")
    return FileResponse(INDEX_FILE)


@app.get("/api/health")
def health():
    return {"status": "ok", "service": "Secure AI Gateway", "mode": "demo",
            "llm": "groq" if isinstance(_llm, GroqLLM) else "mock"}


@app.get("/api/demo-users")
def demo_users():
    return {"users": sorted(DEMO_USERS), "authentication": "demo-only"}


@app.post("/api/chat")
def chat(request: ChatRequest):
    user = request.user.strip().lower()
    message = request.message.strip()
    if user not in DEMO_USERS:
        raise HTTPException(status_code=400, detail="Unknown demo user.")
    if not message:
        raise HTTPException(status_code=400, detail="Message cannot be empty.")
    try:
        token = world.tok(user)
        result = gateway.handle(token, message)
        ok = bool(get_result_field(result, "ok", default=False))
        answer = get_result_field(result, "text", "answer", "response", "output", "message",
                                   default="No response message returned.")
        return {
            "ok": ok,
            "status": "allowed" if ok else "blocked",
            "user": user,
            "answer": str(answer),
            "blocked_by": get_result_field(result, "blocked_by", default=None),
            "findings": json_safe(get_result_field(result, "findings", default=[]) or []),
            "tool_blocks": json_safe(get_result_field(result, "tool_blocks", default=[]) or []),
            "request_id": get_result_field(result, "request_id", default=None),
        }
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(status_code=500,
            detail="Gateway request failed. Check the server terminal.") from None


@app.get("/api/benchmark/latest")
def benchmark_latest():
    run_dir = _latest_benchmark_run()
    if run_dir is None:
        raise HTTPException(status_code=404, detail="No benchmark runs found.")
    payload = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    return {"run_id": run_dir.name, **payload}


@app.get("/api/benchmark/runs")
def benchmark_runs():
    runs = _all_benchmark_runs()
    return {"runs": runs, "count": len(runs)}


@app.get("/api/benchmark/run/{run_id}")
def benchmark_run(run_id: str):
    if not run_id.replace("T", "").replace("Z", "").isalnum():
        raise HTTPException(status_code=400, detail="Invalid run ID.")
    report = BENCHMARKS_DIR / run_id / "report.json"
    if not report.is_file():
        raise HTTPException(status_code=404, detail=f"Run {run_id!r} not found.")
    payload = json.loads(report.read_text(encoding="utf-8"))
    return {"run_id": run_id, **payload}


@app.get("/benchmark", response_class=HTMLResponse)
def benchmark_page():
    from web_app_benchmark_template import render_benchmark_page
    return HTMLResponse(content=render_benchmark_page(_all_benchmark_runs()), media_type="text/html")


@app.get("/admin", response_class=HTMLResponse)
def admin_page():
    admin_file = STATIC_DIR / "admin.html"
    if not admin_file.is_file():
        raise HTTPException(status_code=500, detail="static/admin.html is missing.")
    return FileResponse(admin_file)


@app.get("/api/admin/stats")
def admin_stats():
    return get_admin_stats()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=os.getenv("HOST", "0.0.0.0"), port=int(os.getenv("PORT", "8000")))