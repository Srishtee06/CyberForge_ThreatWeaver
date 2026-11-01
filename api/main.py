"""
CyberForge / ThreatWeaver Main API Entrypoint
Serves REST API, WebSocket live streaming, and Dark Mode Cybersecurity Web Console.
"""

import os
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, HTMLResponse
from api.routes import router as api_router, refresh_incidents, live_monitor

app = FastAPI(
    title="CyberForge / ThreatWeaver — Kill Chain & Attack Path Analysis Engine",
    description="Scalable Out-of-Core Threat Provenance Graph with Look-Ahead Reachability, What-If Blast Radius Simulation, and Boardroom Translation.",
    version="2.0.0"
)

# Enable CORS for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount REST API router
app.include_router(api_router)

# Mount static web directory
static_dir = os.path.abspath("web/static")
os.makedirs(static_dir, exist_ok=True)
app.mount("/static", StaticFiles(directory=static_dir), name="static")


@app.get("/", response_class=HTMLResponse)
def serve_index():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return HTMLResponse("<h1>ThreatWeaver Engine Active. Web Console loading...</h1>")


@app.get("/threatweaver.html", response_class=HTMLResponse)
def serve_threatweaver_html():
    index_file = os.path.join(static_dir, "index.html")
    if os.path.exists(index_file):
        return FileResponse(index_file)
    return FileResponse(os.path.abspath("threatweaver.html"))


@app.get("/threatweaver_console.html", response_class=HTMLResponse)
def serve_threatweaver_console_html():
    console_file = os.path.abspath("threatweaver_console.html")
    if os.path.exists(console_file):
        return FileResponse(console_file)
    return FileResponse(os.path.join(static_dir, "index.html"))


@app.get("/download-readme")
def download_readme():
    readme_path = os.path.abspath("README.md")
    if os.path.exists(readme_path):
        return FileResponse(
            readme_path,
            media_type="text/markdown",
            filename="ThreatWeaver_README.md"
        )
    return HTMLResponse("<h3>README.md not found</h3>", status_code=404)


@app.get("/download-package")
def download_package():
    pkg_path = os.path.abspath("threatweaver_package.zip")
    if os.path.exists(pkg_path):
        return FileResponse(
            pkg_path,
            media_type="application/zip",
            filename="threatweaver_package.zip"
        )
    return HTMLResponse("<h3>threatweaver_package.zip not found</h3>", status_code=404)


# Real-time WebSocket connection for live telemetry stream (Bonus B-5)
active_connections = set()


@app.websocket("/ws/live")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            # Ingest live line and broadcast update
            event = live_monitor.ingest_live_log_line(data)
            if event:
                refresh_incidents()
                for conn in list(active_connections):
                    try:
                        await conn.send_json({"type": "NEW_ATTACK_STEP", "event": event})
                    except Exception:
                        active_connections.discard(conn)
    except WebSocketDisconnect:
        active_connections.discard(websocket)

