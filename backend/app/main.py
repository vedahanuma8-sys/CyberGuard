from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.v1.router import api_router
from app.core.config import settings
from app.ml_engines.dos_engine import DoSEngine
from app.ml_engines.phishing_engine import PhishingEngine
from app.ml_engines.spam_engine import SpamEngine


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan context manager that pre-loads ML engines into app.state at startup."""
    print("--- Initializing CyberGuard ML Inference Engines ---")
    app.state.phishing_engine = PhishingEngine(settings.ARTIFACTS_DIR / "phishing_model.joblib")
    app.state.spam_engine = SpamEngine(settings.ARTIFACTS_DIR / "spam_pipeline.joblib")
    app.state.dos_engine = DoSEngine(settings.ARTIFACTS_DIR / "dos_model.joblib")
    print("All ML engines successfully pre-loaded into memory.")
    yield
    print("--- Shutting down CyberGuard ML Inference Engines ---")


app = FastAPI(
    title=settings.PROJECT_NAME,
    openapi_url=f"{settings.API_V1_STR}/openapi.json",
    lifespan=lifespan,
)

# Set up CORS middleware
if settings.BACKEND_CORS_ORIGINS:
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.BACKEND_CORS_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

# Mount API v1 router
app.include_router(api_router, prefix=settings.API_V1_STR)


@app.get("/health", tags=["System"])
def health_check() -> Dict[str, Any]:
    """Health check endpoint returning engine readiness and artifact file sizes."""
    artifact_files = ["phishing_model.joblib", "spam_pipeline.joblib", "dos_model.joblib"]
    artifacts_status = {}

    for name in artifact_files:
        path = settings.ARTIFACTS_DIR / name
        exists = path.exists()
        size = path.stat().st_size if exists else 0
        artifacts_status[name] = {
            "exists": exists,
            "size_bytes": size,
        }

    engines_ready = {
        "phishing_engine": getattr(app.state, "phishing_engine", None) is not None,
        "spam_engine": getattr(app.state, "spam_engine", None) is not None,
        "dos_engine": getattr(app.state, "dos_engine", None) is not None,
    }

    all_ready = all(engines_ready.values())

    return {
        "status": "healthy" if all_ready else "degraded",
        "all_engines_ready": all_ready,
        "engines": engines_ready,
        "artifacts": artifacts_status,
        "artifacts_dir": str(settings.ARTIFACTS_DIR),
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
