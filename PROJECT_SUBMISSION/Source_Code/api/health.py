import os
from urllib import request

import psycopg
import redis
from qdrant_client import QdrantClient

from knowledge_graph.client import Neo4jClient


def _check_postgres() -> tuple[str, str | None]:
    database_url = os.getenv("DATABASE_URL")

    if not database_url:
        return "not_configured", "DATABASE_URL is not configured."

    try:
        with psycopg.connect(
            database_url,
            connect_timeout=3,
        ) as connection:
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1")
                cursor.fetchone()

        return "ok", None

    except Exception as exc:
        return "unavailable", str(exc)


def _check_redis() -> tuple[str, str | None]:
    redis_url = os.getenv("REDIS_URL")

    if not redis_url:
        return "not_configured", "REDIS_URL is not configured."

    client = None

    try:
        client = redis.Redis.from_url(
            redis_url,
            socket_connect_timeout=3,
            socket_timeout=3,
        )

        client.ping()

        return "ok", None

    except Exception as exc:
        return "unavailable", str(exc)

    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _check_qdrant() -> tuple[str, str | None]:
    qdrant_url = os.getenv("QDRANT_URL")

    if not qdrant_url:
        return "not_configured", "QDRANT_URL is not configured."

    client = None

    try:
        client = QdrantClient(
            url=qdrant_url,
            timeout=3,
        )

        client.get_collections()

        return "ok", None

    except Exception as exc:
        return "unavailable", str(exc)

    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _check_neo4j() -> tuple[str, str | None]:
    required = (
        "NEO4J_URI",
        "NEO4J_USERNAME",
        "NEO4J_PASSWORD",
        "NEO4J_DATABASE",
    )

    missing = [
        name
        for name in required
        if not os.getenv(name)
    ]

    if missing:
        return (
            "not_configured",
            "Missing: " + ", ".join(missing),
        )

    client = None

    try:
        client = Neo4jClient()
        client.verify_connectivity()

        return "ok", None

    except Exception as exc:
        return "unavailable", str(exc)

    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                pass


def _check_ollama() -> tuple[str, str | None]:
    base_url = os.getenv(
        "OLLAMA_BASE_URL",
        "http://127.0.0.1:11434",
    ).rstrip("/")

    try:
        http_request = request.Request(
            url=f"{base_url}/api/tags",
            method="GET",
        )

        with request.urlopen(
            http_request,
            timeout=3,
        ) as response:
            if response.status != 200:
                return (
                    "unavailable",
                    f"Ollama returned HTTP {response.status}.",
                )

        return "ok", None

    except Exception as exc:
        return "unavailable", str(exc)


def readiness_status() -> dict:
    checks = {
        "postgresql": _check_postgres(),
        "redis": _check_redis(),
        "qdrant": _check_qdrant(),
        "neo4j": _check_neo4j(),
        "ollama": _check_ollama(),
    }

    dependencies = {}

    for name, (status, error) in checks.items():
        item = {"status": status}

        if error:
            item["error"] = error

        dependencies[name] = item

    ready = all(
        status == "ok"
        for status, _ in checks.values()
    )

    return {
        "status": "ready" if ready else "not_ready",
        "service": "autonomous-ai-cybersecurity",
        "dependencies": dependencies,
    }
