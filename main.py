from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import ollama
from laya import Router 
import docker
import datetime

app = FastAPI()
# Enable CORS so the local HTML file can fetch data
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

# Initialize Laya (System 1) and Docker (Execution Isolation)
laya_router = Router()
client = docker.from_env()

# In-memory database for the hackathon dashboard
audit_logs = []

class AgentCommand(BaseModel):
    command: str
    context: str

@app.post("/api/v1/intercept")
def intercept(payload: AgentCommand):
    # 1. System 1 Fast Check (Laya)
    questions = {
        "safety": {
            "type": "choice",
            "instructions": "Is this command safe to execute on a local developer machine?",
            "criteria": {
                "SAFE": "Harmless commands like ls, echo, pwd, pytest",
                "UNSAFE": "Destructive commands like rm -rf, mkfs, format, chmod 777",
                "AMBIGUOUS": "Network requests or package installs like wget, curl, npm install"
            }
        }
    }
    
    # Laya returns a structured JSON decision in ~33ms without generative hallucination
    laya_result = laya_router.predict(f"Command: {payload.command} | Context: {payload.context}", questions)
    decision = laya_result["answers"]["safety"]["choice"].upper()
    
    log_entry = {
        "time": datetime.datetime.now().strftime("%H:%M:%S"),
        "command": payload.command,
        "layer": "System 1 (Laya)",
        "decision": decision,
        "output": ""
    }

    # Immediate Reject path
    if decision == "UNSAFE":
        log_entry["output"] = "BLOCKED: Destructive command detected."
        audit_logs.append(log_entry)
        return log_entry

    # Escalation path
    if decision == "AMBIGUOUS":
        log_entry["layer"] = "System 2 (Qwen3 LLM)"
        prompt = f"Analyze this command for supply chain risks. Command: {payload.command}. Context: {payload.context}. Reply exactly with SAFE or REQUEST_APPROVAL."
        
        # Local, open-weight evaluation (No data leaves the machine)
        qwen_resp = ollama.chat(model='qwen3', messages=[{'role': 'user', 'content': prompt}])
        qwen_decision = qwen_resp['message']['content'].strip()
        
        if "REQUEST_APPROVAL" in qwen_decision:
            log_entry["decision"] = "PENDING_APPROVAL"
            log_entry["output"] = "Paused for human review by AI security layer."
            audit_logs.append(log_entry)
            return log_entry
        else:
            decision = "SAFE"

    # Execution path
    if decision == "SAFE":
        try:
            # Ephemeral, read-only Docker container
            container = client.containers.run(
                "ubuntu:latest",
                payload.command,
                network_disabled=True,
                read_only=True,
                remove=True,
                mem_limit="128m"
            )
            log_entry["output"] = container.decode("utf-8").strip()
        except Exception as e:
            log_entry["output"] = f"Execution error: {str(e)}"
            
    audit_logs.append(log_entry)
    return log_entry

@app.get("/api/v1/logs")
def get_logs():
    # Return newest logs first for the dashboard
    return audit_logs[::-1]