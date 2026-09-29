from pathlib import Path
from typing import List
from pydantic import ConfigDict

try:
    from pydantic_settings import BaseSettings
except ImportError:
    try:
        from pydantic import BaseSettings
    except ImportError:
        from pydantic import BaseModel as BaseSettings

# Base directory for the backend app
APP_DIR = Path(__file__).resolve().parent.parent

class Settings(BaseSettings):
    model_config = ConfigDict(case_sensitive=True, extra="ignore")

    PROJECT_NAME: str = "CyberGuard Threat Intelligence Platform"
    API_V1_STR: str = "/api/v1"
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    ARTIFACTS_DIR: Path = APP_DIR / "models" / "artifacts"

settings = Settings()
