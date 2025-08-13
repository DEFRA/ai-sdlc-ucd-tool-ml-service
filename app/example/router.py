from logging import getLogger

from fastapi import APIRouter, Depends

from app.common.http_client import async_client

router = APIRouter(prefix="/example")
logger = getLogger(__name__)


# remove this example route
@router.get("/test")
async def root():
    logger.info("TEST ENDPOINT")
    return {"ok": True}


@router.get("/http")
async def http_query(client=Depends(async_client)):
    resp = await client.get("http://localstack:4566/health")
    return {"ok": resp.status_code}
