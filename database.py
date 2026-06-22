from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from sqlalchemy import text
from sqlmodel import Field, Session, SQLModel, create_engine


DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DATA_DIR / 'watchmylan.db'}")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Device(SQLModel, table=True):
    mac: str = Field(primary_key=True, index=True)
    ip: str = Field(index=True)
    hostname: str = Field(default="")
    custom_name: str = Field(default="")
    notes: str = Field(default="")
    first_seen: datetime = Field(default_factory=utc_now)
    last_seen: datetime = Field(default_factory=utc_now, index=True)
    status: str = Field(default="Online", index=True)
    missed_scans: int = Field(default=0)
    known: bool = Field(default=False, index=True)
    connected_since: Optional[datetime] = Field(default=None)
    vendor: str = Field(default="")
    device_type: str = Field(default="Otro", index=True)
    favorite: bool = Field(default=False, index=True)
    open_ports: str = Field(default="[]")
    services_updated_at: Optional[datetime] = Field(default=None)
    latency_ms: Optional[float] = Field(default=None)
    latency_updated_at: Optional[datetime] = Field(default=None)


class DeviceUpdate(SQLModel):
    custom_name: Optional[str] = None
    notes: Optional[str] = None
    known: Optional[bool] = None
    device_type: Optional[str] = None
    favorite: Optional[bool] = None


class AppSetting(SQLModel, table=True):
    key: str = Field(primary_key=True)
    value: str = Field(default="")
    updated_at: datetime = Field(default_factory=utc_now)


class ConnectionEvent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    mac: str = Field(index=True)
    event_type: str = Field(index=True)
    occurred_at: datetime = Field(default_factory=utc_now, index=True)
    ip: str = Field(default="")


class ScanSnapshot(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    occurred_at: datetime = Field(default_factory=utc_now, index=True)
    found: int = 0
    online: int = 0
    offline: int = 0
    unknown: int = 0
    duration_ms: int = 0


class DeviceMetric(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    mac: str = Field(index=True)
    occurred_at: datetime = Field(default_factory=utc_now, index=True)
    latency_ms: float


class Agent(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str = Field(index=True)
    subnet: str = ""
    token: str = Field(index=True)
    enabled: bool = True
    last_seen: Optional[datetime] = None


def init_db() -> None:
    SQLModel.metadata.create_all(engine)
    # create_all no altera tablas SQLite existentes; estas migraciones son idempotentes.
    with engine.begin() as connection:
        columns = {row[1] for row in connection.execute(text("PRAGMA table_info(device)"))}
        if "known" not in columns:
            connection.execute(text("ALTER TABLE device ADD COLUMN known BOOLEAN NOT NULL DEFAULT 0"))
        if "connected_since" not in columns:
            connection.execute(text("ALTER TABLE device ADD COLUMN connected_since DATETIME"))
        additions = {
            "vendor": "VARCHAR NOT NULL DEFAULT ''",
            "device_type": "VARCHAR NOT NULL DEFAULT 'Otro'",
            "favorite": "BOOLEAN NOT NULL DEFAULT 0",
            "open_ports": "VARCHAR NOT NULL DEFAULT '[]'",
            "services_updated_at": "DATETIME",
            "latency_ms": "FLOAT",
            "latency_updated_at": "DATETIME",
        }
        for name, definition in additions.items():
            if name not in columns:
                connection.execute(text(f"ALTER TABLE device ADD COLUMN {name} {definition}"))


def get_session():
    with Session(engine) as session:
        yield session
