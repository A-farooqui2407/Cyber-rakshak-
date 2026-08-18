import os
from typing import List
from pydantic_settings import BaseSettings

class Settings(BaseSettings):
    PROJECT_NAME: str = "CyberRakshak API"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Supabase Configuration
    SUPABASE_URL: str = os.getenv("SUPABASE_URL", "")
    SUPABASE_ANON_KEY: str = os.getenv("SUPABASE_ANON_KEY", "")
    SUPABASE_SERVICE_ROLE_KEY: str = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "")
    
    # LLM Configuration
    LLM_API_KEY: str = os.getenv("LLM_API_KEY", os.getenv("GEMINI_API_KEY", ""))
    LLM_MODEL: str = os.getenv("LLM_MODEL", "gemini-3.7-flash")
    LLM_API_BASE_URL: str = os.getenv("LLM_API_BASE_URL", "https://generativelanguage.googleapis.com/v1beta")
    
    # Security & CORS
    ALLOWED_ORIGINS: List[str] = [
        origin.strip() for origin in os.getenv("ALLOWED_ORIGINS", "http://localhost:3000,http://localhost:5173,http://127.0.0.1:3000").split(",")
    ]
    
    # Detection Engine Thresholds
    FAILED_LOGIN_THRESHOLD: int = 5
    FAILED_LOGIN_WINDOW_MINUTES: int = 5
    SUSPICIOUS_DATA_ACCESS_THRESHOLD: int = 20
    
    class Config:
        case_sensitive = True
        env_file = ".env"

settings = Settings()
