from fastapi import FastAPI
from app.api.v1.endpoints import category_1_process
from app.api.v1.endpoints import scan
from app.api.v1.endpoints import llm_check
from app.api.v1.endpoints import classifier_check

app = FastAPI(title="MalPack Backend")

from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ── Legacy routes (backward compatibility) ──────────────────────────────────
app.include_router(category_1_process.router, prefix="/api/v1/process", tags=["Process"])
app.include_router(scan.router, prefix="/api/v1/scan", tags=["Scan"])

# ── New detection-method-specific routes ─────────────────────────────────────
# Semgrep-based check: /api/v1/semgrep_check/check
app.include_router(scan.router, prefix="/api/v1/semgrep_check", tags=["Semgrep Check"])

# Rule-based check: /api/v1/rule_based_check/check
app.include_router(scan.router, prefix="/api/v1/rule_based_check", tags=["Rule Based Check"])

# LLM-based check: /api/v1/llm_based_check
app.include_router(llm_check.router, prefix="/api/v1", tags=["LLM Check"])

# Classifier-based check (stub): /api/v1/classifier_based_check
app.include_router(classifier_check.router, prefix="/api/v1", tags=["Classifier Check"])


@app.get("/")
def read_root():
    return {"status": "MalPack Backend Running"}