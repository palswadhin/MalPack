"""
LLM-Based Malicious Package Analysis using Google Gemini API.
Sends each Python file to Gemini for security analysis and merges results.
No code-level findings - only a high-level summary is returned.
"""
from fastapi import APIRouter, Body
from typing import List, Dict, Any
from google import genai
from google.genai import types
import os
from dotenv import load_dotenv

load_dotenv()

# Configure the Gemini API key from environment variables
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if GEMINI_API_KEY:
    client = genai.Client(api_key=GEMINI_API_KEY)
else:
    import logging
    logging.warning("GEMINI_API_KEY not set! LLM endpoints will return errors.")
    client = None

router = APIRouter()

def _clean_error(e: Exception) -> str:
    """Extract a short, human-readable error message from Gemini API exceptions."""
    msg = str(e)
    if 'RESOURCE_EXHAUSTED' in msg or 'quota' in msg.lower():
        return 'Gemini API quota exceeded. Please wait for reset or use a different API key.'
    if '404' in msg and 'not found' in msg.lower():
        return 'Gemini model not found. The model may have been deprecated.'
    if '403' in msg or 'PERMISSION_DENIED' in msg:
        return 'Gemini API key is invalid or lacks permissions.'
    if '401' in msg or 'UNAUTHENTICATED' in msg:
        return 'Gemini API key is invalid. Please check your GEMINI_API_KEY.'
    # Fallback: truncate long messages
    if len(msg) > 120:
        return msg[:120] + '...'
    return msg

SECURITY_PROMPT_TEMPLATE = """You are a cybersecurity expert specialized in detecting malicious Python packages.
Analyze the following Python source code for malicious behavior. 

Look for indicators such as:
- Unauthorized data exfiltration (sending data to external servers, environment variable theft)
- Backdoors or remote access (reverse shells, command-and-control communication)
- Credential theft (accessing keychains, password files, browser stored passwords)
- Persistence mechanisms (modifying startup files, cron jobs, registry modifications)
- Supply chain attacks (typosquatting, dependency confusion payloads)
- Obfuscation techniques (base64 encoded payloads, eval of dynamic strings, hex shellcode)
- Cryptomining or ransomware patterns
- Suspicious process execution (os.system, subprocess with external URLs)
- Suspicious network connections to known malicious patterns

File: {file_path}

```python
{content}
```

Respond ONLY with a valid JSON object in this exact format (no markdown, no code blocks):
{{
  "is_malicious": true or false,
  "confidence": "HIGH" or "MEDIUM" or "LOW",
  "indicators": ["indicator 1", "indicator 2"],
  "summary": "Brief explanation of findings or why it appears safe"
}}
"""

def analyze_file_with_gemini(file_path: str, content: str) -> Dict[str, Any]:
    """
    Send a single file to Gemini API for security analysis.
    Returns parsed JSON result.
    """
    if client is None:
        return {
            "file": file_path,
            "is_malicious": False,
            "confidence": "LOW",
            "indicators": [],
            "summary": "GEMINI_API_KEY not configured on the server. Please set it in your environment variables.",
            "error": True
        }
    try:
        prompt = SECURITY_PROMPT_TEMPLATE.format(
            file_path=file_path,
            content=content[:8000]  # Limit to 8000 chars to stay within token limits
        )
        response = client.models.generate_content(
            model='gemini-2.0-flash',
            contents=prompt,
        )
        text = response.text.strip()

        # Clean up possible markdown code fences
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1]) if lines[-1] == "```" else "\n".join(lines[1:])
        elif text.startswith("json\n"):
            text = text[5:]
            
        import json
        result = json.loads(text)
        result["file"] = file_path
        return result

    except Exception as e:
        # If Gemini call fails, return safe default with error info
        return {
            "file": file_path,
            "is_malicious": False,
            "confidence": "LOW",
            "indicators": [],
            "summary": f"Analysis failed: {_clean_error(e)}",
            "error": True
        }

@router.post("/llm_file_check")
async def llm_file_check(
    file_path: str = Body(..., embed=True),
    content: str = Body(..., embed=True),
    is_base64: bool = Body(False, embed=True)
):
    """
    Check a single file using the LLM for malicious intent.
    Used for one-by-one logging in the extension.
    """
    if is_base64:
        import base64
        content = base64.b64decode(content).decode('utf-8', errors='ignore')
        
    if not file_path.endswith(".py") or len(content.strip()) < 10:
        return {
            "file": file_path,
            "is_malicious": False,
            "confidence": "LOW",
            "indicators": [],
            "summary": "Skipped non-python or empty file",
            "error": False
        }
        
    return analyze_file_with_gemini(file_path, content)


@router.post("/llm_based_check")
async def llm_based_check(
    package_name: str = Body(..., embed=False),
    files: List[Dict[str, Any]] = Body(..., embed=False)
):
    """
    Legacy endpoint for LLM-based analysis using Gemini API (batch).
    """
    file_results = []
    malicious_files = []
    all_indicators = []
    errors = []

    for file_info in files:
        file_path = file_info.get("file_path", "unknown.py")
        content = file_info.get("content", "")
        if file_info.get("is_base64"):
            import base64
            content = base64.b64decode(content).decode('utf-8', errors='ignore')

        # Only analyze Python files with actual content
        if not file_path.endswith(".py") or len(content.strip()) < 10:
            continue

        result = analyze_file_with_gemini(file_path, content)
        file_results.append(result)

        if result.get("error"):
            errors.append(file_path)

        if result.get("is_malicious"):
            malicious_files.append({
                "file": file_path,
                "confidence": result.get("confidence", "LOW"),
                "indicators": result.get("indicators", []),
                "summary": result.get("summary", "")
            })
            all_indicators.extend(result.get("indicators", []))

    is_malicious = len(malicious_files) > 0
    verdict = "MALICIOUS" if is_malicious else "BENIGN"

    # Build overall summary
    if is_malicious:
        unique_indicators = list(set(all_indicators))
        overall_summary = (
            f"Package '{package_name}' contains malicious indicators in "
            f"{len(malicious_files)} out of {len(file_results)} analyzed file(s). "
            f"Key findings: {'; '.join(unique_indicators[:5])}"
            if unique_indicators else
            f"Package '{package_name}' was flagged as potentially malicious by LLM analysis."
        )
    else:
        overall_summary = (
            f"Package '{package_name}' appears safe. "
            f"Analyzed {len(file_results)} Python file(s) with no malicious indicators detected."
        )

    return {
        "verdict": verdict,
        "package_name": package_name,
        "files_analyzed": len(file_results),
        "malicious_files_count": len(malicious_files),
        "summary": overall_summary,
        "malicious_files": malicious_files,
        "analysis_errors": errors
    }

SUGGEST_PROMPT = """You are a Python ecosystem expert.
The user wanted to install the pip package '{package_name}', but it was detected as MALICIOUS or UNSAFE.
Can you suggest 3 safe, popular, and well-maintained alternative packages that provide similar functionality to what '{package_name}' is typically used for (or might be typosquatting)?

Respond ONLY with a valid JSON object in this exact format (no markdown, no blocks):
{{
  "alternatives": [
    {{"name": "package1", "reason": "brief reason why it's a good alternative"}},
    {{"name": "package2", "reason": "..."}},
    {{"name": "package3", "reason": "..."}}
  ]
}}
"""

@router.post("/suggest_alternatives")
async def suggest_alternatives(
    package_name: str = Body(..., embed=True),
):
    """
    Suggests alternative packages using Gemini API.
    """
    if client is None:
        return {
            "success": False,
            "error": "GEMINI_API_KEY not configured on the server. Please set it in your Render environment variables.",
            "alternatives": []
        }
    try:
        prompt = SUGGEST_PROMPT.format(package_name=package_name)
        response = client.models.generate_content(
            model='gemini-2.0-flash',
            contents=prompt,
        )
        text = response.text.strip()
        
        if text.startswith("```"):
            lines = text.split("\n")
            text = "\n".join(lines[1:-1]) if lines[-1] == "```" else "\n".join(lines[1:])
        elif text.startswith("json\n"):
            text = text[5:]
            
        import json
        result = json.loads(text)
        return {
            "success": True,
            "alternatives": result.get("alternatives", [])
        }
    except Exception as e:
        return {
            "success": False,
            "error": _clean_error(e),
            "alternatives": []
        }
