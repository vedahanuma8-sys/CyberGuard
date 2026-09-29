from fastapi import APIRouter
from app.api.v1.endpoints import threats

api_router = APIRouter()
api_router.include_router(threats.router, prefix="/analyze", tags=["Threat Analysis"])
