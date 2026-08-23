from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.config import BASE_DIR, settings
from app.database import SessionLocal, init_db
from app.routers.web import router
from app.services.policies import import_policies


@asynccontextmanager
async def lifespan(_: FastAPI):
    if settings.app_env == "production" and settings.secret_key in {"change-me-in-production", "change-this-before-production", "replace-this-for-production"}:
        raise RuntimeError("SECRET_KEY must be configured for production")
    init_db()
    with SessionLocal() as db:
        import_policies(db)
    yield


def create_app() -> FastAPI:
    application = FastAPI(
        title=settings.app_name,
        description="Cloud Security Posture Management, Terraform scanning, policy-as-code, compliance, and DevSecOps assessment platform.",
        version="1.0.0",
        lifespan=lifespan,
    )
    application.add_middleware(SessionMiddleware, secret_key=settings.secret_key, same_site="lax", https_only=settings.app_env == "production")
    application.mount("/static", StaticFiles(directory=str(BASE_DIR / "app" / "static")), name="static")
    application.include_router(router)

    @application.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self' https://cdn.jsdelivr.net; style-src 'self'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'"
        return response

    return application


app = create_app()
