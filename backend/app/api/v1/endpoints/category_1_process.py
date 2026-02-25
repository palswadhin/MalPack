from fastapi import APIRouter, Body
from app.engine.ast_engine import run_ast_scan
from app.engine.semgrep_engine import run_semgrep
# Import the list of 8 rules from the folder
from app.engine.rules.process import PROCESS_RULES 

router = APIRouter()

@router.post("/check")
async def check_process(
    file_path: str = Body(...),
    content: str = Body(...),
    is_base64: bool = Body(False)
):
    import base64
    if is_base64:
        content = base64.b64decode(content).decode('utf-8')
    findings = []

    # 1. Run the 8 Manual AST Files
    ast_res = run_ast_scan(content, PROCESS_RULES)
    findings.extend([f"[AST] {r['message']}" for r in ast_res])

    # 2. Run the Semgrep Rule
    sem_res = run_semgrep(content, "app/engine/semgrep_rules/process.yaml")
    findings.extend([f"[SEMGREP] {m}" for m in sem_res])

    return {
        "file": file_path,
        "status": "DANGER" if findings else "SAFE",
        "violations": findings
    }