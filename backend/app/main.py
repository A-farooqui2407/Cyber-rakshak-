from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .core.config import settings
from .api.endpoints import router as api_router

app = FastAPI(
    title="CyberRakshak — Affordable SOC-in-a-Box API",
    description="Lightweight SIEM and automated Security Operations Center backend with deterministic risk scoring, correlation engine, and AI threat analysis.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json"
)

# CORS Middleware setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health", tags=["System"])
async def health_check():
    """
    Health check endpoint verifying CyberRakshak API status.
    """
    return {
        "status": "ok",
        "service": "CyberRakshak API",
        "version": settings.VERSION,
        "detection_engine": "online",
        "database": "connected"
    }

# Mount REST API
app.include_router(api_router, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
