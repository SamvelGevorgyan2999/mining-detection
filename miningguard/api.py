from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import timedelta

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request  # type: ignore[reportMissingImports]
from fastapi.responses import FileResponse, JSONResponse # type: ignore[reportMissingImports]
from fastapi.staticfiles import StaticFiles # type: ignore[reportMissingImports]
from sqlalchemy import func, select # type: ignore[reportMissingImports]
from sqlalchemy.orm import Session # type: ignore[reportMissingImports]

from . import intel, rules, service
from .config import WEB_ROOT, settings
from .db import init_db, session_dependency
from .models import Alert, Detection, Host, NetworkEvent, PersistenceItem, Process, utcnow
from .schemas import (
    ALERT_STATUSES,
    AlertDetailOut,
    AlertUpdateIn,
    DetectionOut,
    DetectionWithHostOut,
    HostDetailOut,
    HostSummaryOut,
    IngestResultOut,
    NetworkEventOut,
    PersistenceOut,
    ProcessOut,
    SnapshotIn,
    StatsOut,
)

@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    init_db()
    intel.load_feed(settings.feed_path)
    yield


app = FastAPI(
    title="MiningGuard",
    version="1.0.0",
    description="Cryptomining and cryptojacking detection API",
    lifespan=lifespan,
)

