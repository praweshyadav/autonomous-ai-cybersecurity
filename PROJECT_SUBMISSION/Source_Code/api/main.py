import time

from dotenv import load_dotenv
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

load_dotenv()

from api.health import readiness_status
from api.incidents import router as incidents_router
from app.metrics import (
    API_ERRORS_TOTAL,
    API_REQUEST_DURATION_SECONDS,
    API_REQUESTS_TOTAL,
)


app = FastAPI(
    title="Autonomous AI Cybersecurity API",
    version="1.0.0",
    description="REST API for the Autonomous AI Cybersecurity Analyst platform.",
)


app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_credentials=True,
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.middleware("http")
async def prometheus_request_metrics(
    request: Request,
    call_next,
):
    if request.url.path == "/metrics":
        return await call_next(request)

    start_time = time.perf_counter()

    try:
        response = await call_next(request)
    except Exception:
        duration = time.perf_counter() - start_time
        path = request.url.path
        method = request.method

        API_REQUEST_DURATION_SECONDS.labels(
            method=method,
            path=path,
        ).observe(duration)

        API_REQUESTS_TOTAL.labels(
            method=method,
            path=path,
            status="500",
        ).inc()

        API_ERRORS_TOTAL.labels(
            method=method,
            path=path,
            status="500",
        ).inc()

        raise

    duration = time.perf_counter() - start_time
    path = request.scope.get("route").path if request.scope.get("route") else request.url.path
    method = request.method
    status = str(response.status_code)

    API_REQUEST_DURATION_SECONDS.labels(
        method=method,
        path=path,
    ).observe(duration)

    API_REQUESTS_TOTAL.labels(
        method=method,
        path=path,
        status=status,
    ).inc()

    if response.status_code >= 400:
        API_ERRORS_TOTAL.labels(
            method=method,
            path=path,
            status=status,
        ).inc()

    return response


@app.get("/health")
def health() -> dict[str, str]:
    return {
        "status": "ok",
        "service": "autonomous-ai-cybersecurity",
    }


@app.get("/health/ready")
def readiness() -> dict:
    return readiness_status()


@app.get("/metrics")
def metrics() -> Response:
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )


app.include_router(incidents_router)
