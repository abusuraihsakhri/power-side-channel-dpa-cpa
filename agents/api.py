"""
FastAPI REST API Server for Power Side Channel Dpa Cpa.
"""
from typing import Dict, Any, List
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from .base import AuditLogger, PHIGuard, SecurityException
from .models import SystemTaskPayload, ConsensusDossier
from .supervisor import SystemSupervisor

supervisor = SystemSupervisor(model_provider="mock")

app = FastAPI(
    title="Power Side Channel Dpa Cpa API",
    description="Enterprise Distributed Component Platform (Post-Quantum Cryptography & Hardware Security)",
    version="3.0.0-ENTERPRISE",
)

@app.exception_handler(SecurityException)
async def sensitive_input_handler(request: Request, exc: SecurityException):
    return JSONResponse(status_code=400, content={"detail": "Sensitive identifiers are not accepted."})


_web_dir = Path(__file__).resolve().parent.parent / "web"
if _web_dir.is_dir():
    app.mount("/app", StaticFiles(directory=str(_web_dir), html=True), name="static-app")

    @app.get("/", include_in_schema=False)
    def application_home():
        return RedirectResponse(url="/app/")



class ChatRequest(BaseModel):
    query: str


@app.get("/health")
def health():
    return {"status": "HEALTHY", "service": "power-side-channel-dpa-cpa", "domain": "Post-Quantum Cryptography & Hardware Security", "standard": "NIST FIPS 203/204/205 / ISO/IEC 17825 Standards", "version": "3.0.0-ENTERPRISE"}


@app.get("/metrics")
def metrics():
    return {
        "dossiers_processed_total": len(supervisor.dossier_registry),
        "audit_blocks_total": len(AuditLogger.get_trail()),
        "system_status": "NOMINAL_OPTIMAL"
    }


@app.post("/api/audit")
def api_audit(payload: SystemTaskPayload):
    dossier = supervisor.process_task(payload)
    return dossier.to_dict()


@app.post("/api/chat")
def api_chat(req: ChatRequest):
    try:
        ans = supervisor.query_supervisory_chat(req.query)
        return {"response": ans}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/api/audit/logs")
def api_audit_logs():
    return {"audit_trail": AuditLogger.get_trail(), "verified": AuditLogger.verify_integrity()}
