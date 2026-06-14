from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(
    title="BT Threat Intel API",
    description="Internal API for the BT Threat Intel platform",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:8501"],  # Streamlit default port
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
def health_check():
    return {"status": "ok"}


# TODO: add routers as modules are built out
# from src.api.routes import threats, chat, alerts
# app.include_router(threats.router, prefix="/threats")
# app.include_router(chat.router, prefix="/chat")
# app.include_router(alerts.router, prefix="/alerts")
