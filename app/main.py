"""FastAPI application entry point."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager
from typing import Any

import uvicorn
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, PlainTextResponse

from app.api import admin, chat, health, nexus
from app.config.settings import settings
from app.runtime import ApplicationServices
from app.utils.audit import audit_logger
from app.utils.auth import require_admin_token
from app.utils.logging import get_logger


logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    services = ApplicationServices()
    app.state.services = services
    await services.startup()
    logger.info("Started %s v%s", settings.APP_NAME, settings.APP_VERSION)
    audit_logger.log_system_event(
        event="application_startup",
        component="main",
        details={"environment": settings.ENVIRONMENT, "version": settings.APP_VERSION},
    )
    try:
        yield
    finally:
        await services.shutdown()
        audit_logger.log_system_event(
            event="application_shutdown",
            component="main",
            details={"environment": settings.ENVIRONMENT},
        )


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Evidence-grounded operational intelligence for ICT operations.",
    docs_url="/docs" if settings.is_development else None,
    redoc_url="/redoc" if settings.is_development else None,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def observe_requests(request: Request, call_next):
    started = time.perf_counter()
    services = getattr(request.app.state, "services", None)
    request_id = request.headers.get("X-Request-ID", "unknown")
    try:
        response = await call_next(request)
    except Exception:
        if services is not None:
            services.metrics.incr("sentinelops_http_errors_total")
        raise
    elapsed = time.perf_counter() - started
    if services is not None:
        services.metrics.incr("sentinelops_http_requests_total")
        services.metrics.observe("sentinelops_http_request_duration_seconds", elapsed)
        services.metrics.gauge("sentinelops_last_response_status", response.status_code)
    response.headers["X-Request-ID"] = request_id
    return response


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.status_code,
                "message": exc.detail,
                "path": request.url.path,
            }
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    audit_logger.log_validation_failure(
        user=request.headers.get("X-User-ID", "unknown"),
        validation_type="request_validation",
        reason="Invalid request parameters",
        context={"errors": exc.errors(), "path": request.url.path},
    )
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": 422,
                "message": "Validation error",
                "errors": exc.errors(),
            }
        },
    )


@app.exception_handler(Exception)
async def general_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled exception on %s", request.url.path)
    audit_logger.log_system_event(
        event="unhandled_exception",
        component="main",
        details={"path": request.url.path, "error": str(exc)},
        severity="CRITICAL",
    )
    message = "Internal server error" if settings.is_production else str(exc)
    return JSONResponse(
        status_code=500,
        content={"error": {"code": 500, "message": message}},
    )


app.include_router(health.router)
app.include_router(chat.router, prefix="/api/v1", tags=["query"])
app.include_router(nexus.router, prefix="/api/v1", tags=["nexus"])
app.include_router(admin.router, prefix="/api/v1", tags=["admin"])


@app.get("/")
async def root() -> dict[str, Any]:
    return {
        "application": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT,
        "status": "operational",
        "docs": "/docs" if settings.is_development else None,
    }


@app.get("/metrics", response_class=PlainTextResponse)
async def root_metrics(request: Request, _: str = Depends(require_admin_token)) -> str:
    return request.app.state.services.metrics.render_prometheus()


def start() -> None:
    uvicorn.run(
        "app.main:app",
        host=settings.API_HOST,
        port=settings.API_PORT,
        reload=settings.API_RELOAD,
        workers=settings.API_WORKERS,
        log_config=None,
        access_log=False,
    )


if __name__ == "__main__":
    start()
