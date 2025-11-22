from fastapi import FastAPI, HTTPException, Depends, Request
from pydantic import BaseModel
from typing import List, Optional
import logging
import time
import json
import uuid

from pii_vault import PIIVault
from security_scanner import SecurityScanner

# Configure logging
# We want a structured logger for audit trails
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("audit_logger")
# In a real app, we might configure a FileHandler or send logs to ELK/Splunk
# For now, stdout is fine, but we will format it as JSON.

app = FastAPI(title="Enterprise LLM Security Gateway", version="1.1.0")

# Global instances (loaded on startup)
security_scanner = None
pii_vault = None

@app.on_event("startup")
async def startup_event():
    global security_scanner, pii_vault
    logger.info(json.dumps({"event": "startup", "message": "Starting up Enterprise LLM Security Gateway..."}))
    security_scanner = SecurityScanner()
    pii_vault = PIIVault()
    logger.info(json.dumps({"event": "startup", "message": "Security Gateway is ready."}))

class ChatMessage(BaseModel):
    role: str
    content: str

class ChatCompletionRequest(BaseModel):
    model: str
    messages: List[ChatMessage]
    
    class Config:
        extra = "ignore"

class ChatCompletionResponse(BaseModel):
    id: str
    object: str
    created: int
    model: str
    choices: List[dict]

def mock_llm_call(prompt: str) -> str:
    """
    Simulate a call to an external LLM.
    """
    # Simulate network latency
    time.sleep(0.5)
    return f"Echoing your sanitized prompt: {prompt}"

def log_audit(event_type: str, request_id: str, details: dict):
    """
    Helper to log structured audit events.
    """
    log_entry = {
        "timestamp": time.time(),
        "request_id": request_id,
        "event_type": event_type,
        **details
    }
    logger.info(json.dumps(log_entry))

@app.post("/chat/completions", response_model=ChatCompletionResponse)
async def chat_completions(request: ChatCompletionRequest, raw_request: Request):
    """
    Secure Chat Completion Endpoint.
    1. Scans for malicious content.
    2. Anonymizes PII.
    3. Forwards to (Mock) LLM.
    4. Deanonymizes response.
    """
    request_id = str(uuid.uuid4())
    client_ip = raw_request.client.host
    
    # Get Session ID from header or generate a new one
    session_id = raw_request.headers.get("X-Session-ID", str(uuid.uuid4()))
    
    log_audit("request_received", request_id, {"client_ip": client_ip, "model": request.model, "session_id": session_id})

    if not request.messages:
        raise HTTPException(status_code=400, detail="No messages provided.")

    # We only process the last user message for this MVP
    last_message = request.messages[-1]
    user_prompt = last_message.content

    # Step 1: Security Scan
    is_safe = security_scanner.scan(user_prompt)
    if not is_safe:
        log_audit("security_alert", request_id, {"action": "blocked", "reason": "malicious_content", "session_id": session_id})
        raise HTTPException(status_code=403, detail="Security Alert: Malicious prompt detected.")
    
    log_audit("security_scan", request_id, {"status": "passed", "session_id": session_id})

    # Step 2: Anonymize PII (Session Scoped)
    sanitized_prompt = pii_vault.anonymize(user_prompt, session_id)
    
    if sanitized_prompt != user_prompt:
        log_audit("pii_redaction", request_id, {"status": "redacted", "session_id": session_id})
    else:
        log_audit("pii_redaction", request_id, {"status": "no_pii_detected", "session_id": session_id})

    # Step 3: Forward to LLM (Mock)
    llm_raw_response = mock_llm_call(sanitized_prompt)
    
    # Step 4: Deanonymize Response (Session Scoped)
    final_response_text = pii_vault.deanonymize(llm_raw_response, session_id)
    
    log_audit("response_sent", request_id, {"status": "success", "session_id": session_id})
    
    # Construct Response
    response = ChatCompletionResponse(
        id=f"chatcmpl-{request_id}",
        object="chat.completion",
        created=int(time.time()),
        model=request.model,
        choices=[
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": final_response_text
                },
                "finish_reason": "stop"
            }
        ]
    )
    
    return response

@app.get("/health")
async def health_check():
    return {"status": "healthy"}
