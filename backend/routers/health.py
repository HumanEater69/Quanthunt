from fastapi import APIRouter
from backend.mongo_store import mongo_status

router = APIRouter()

@router.get("/health", summary="Basic health check")
@router.get("/api/health", summary="API health check")
def health_check():
    return {
        "status": "ok",
        "timestamp": 12345, # Placeholder
        "db_connected": mongo_status()
    }
