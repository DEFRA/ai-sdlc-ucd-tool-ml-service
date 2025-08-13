from contextlib import asynccontextmanager
from logging import getLogger

from fastapi import FastAPI

from app.auth.auth_middleware import AuthMiddleware
from app.common.mongo import get_mongo_client
from app.common.tracing import TraceIdMiddleware
from app.example.router import router as example_router
from app.health.router import router as health_router

logger = getLogger(__name__)


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Startup
    client = await get_mongo_client()
    logger.info("MongoDB client connected")
    yield
    # Shutdown
    if client:
        await client.close()
        logger.info("MongoDB client closed")


# Configure OpenAPI security schemes
app = FastAPI(
    lifespan=lifespan,
    swagger_ui_init_oauth={
        "clientId": "swagger-ui",
        "appName": "AI SDLC UCD Tool ML Service",
    },
    components={
        "securitySchemes": {
            "bearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "Azure AD JWT token",
            }
        }
    },
)

# Setup middleware
app.add_middleware(AuthMiddleware)
app.add_middleware(TraceIdMiddleware)

# Setup Routes
app.include_router(health_router)
app.include_router(example_router)
