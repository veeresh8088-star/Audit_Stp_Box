from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import os

from src.api.endpoints.auth import router as auth_router
from src.api.endpoints.controls import router as controls_router
from src.api.endpoints.logs import router as logs_router
from src.api.endpoints.audit import router as audit_router

app = FastAPI(
    title="AICyberAuditBox - Local API Server",
    description="Offline REST API Server for RAG ISO 27001 Compliance Audit Intelligence",
    version="1.0.0"
)

from starlette.middleware.base import BaseHTTPMiddleware

class NoCacheMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        response = await call_next(request)
        if request.url.path.startswith("/static") or request.url.path == "/":
            response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, max-age=0"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"
        return response

app.add_middleware(NoCacheMiddleware)

# Enable CORS for local cross-origin React frontend requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all local development origins (Vite/Tauri)
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

# Register endpoints routers
app.include_router(auth_router, prefix="/api")
app.include_router(controls_router, prefix="/api")
app.include_router(logs_router, prefix="/api")
app.include_router(audit_router, prefix="/api")

# Mount static files folder
app.mount("/static", StaticFiles(directory="src/api/static"), name="static")

@app.get("/")
def read_root():
    return FileResponse("src/api/static/index.html")

if __name__ == "__main__":
    port = int(os.environ.get("API_PORT", 8000))
    print(f"Starting AICyberAuditBox Local API server on 127.0.0.1:{port}...", flush=True)
    uvicorn.run("src.api.main:app", host="127.0.0.1", port=port, reload=True)
