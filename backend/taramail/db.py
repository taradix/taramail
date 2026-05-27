"""Database functions."""

import os
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import (
    create_engine,
    delete,
    insert,
)
from sqlalchemy.engine.url import URL
from sqlalchemy.orm import Session as DBSession
from sqlalchemy.orm import sessionmaker


class DBUnsupportedDialectError(Exception):
    """Raised when an unsupported dialect is encountered."""


def get_db_url(env=os.environ) -> URL:
    """Return a database URL from DB variables in the environment."""
    return URL.create(
        drivername=env.get("DBDRIVER", "sqlite"),
        username=env.get("DBUSER"),
        password=env.get("DBPASS"),
        host=env.get("DBHOST"),
        port=env.get("DBPORT"),
        database=env.get("DBNAME"),
    )


@contextmanager
def get_db_session(env=os.environ) -> Iterator[DBSession]:
    """Yield a database session."""
    db_session = SessionLocal()
    try:
        yield db_session
    finally:
        db_session.close()


@contextmanager
def db_transaction(db: DBSession) -> Iterator[DBSession]:
    """Context manager for handling database transactions safely."""
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise


def db_replace_into(db: DBSession, model, values):
    """Portable REPLACE INTO as DELETE + INSERT."""
    pk_cols = list(model.__table__.primary_key)
    pk_values = {col.name: values[col.name] for col in pk_cols}

    db.execute(
        delete(model)
        .where(*(getattr(model, col) == pk_values[col] for col in pk_values))
    )
    db.execute(
        insert(model)
        .values(**values)
    )


DATABASE_URL = get_db_url()

engine = create_engine(
    DATABASE_URL,
    echo=False,
    future=True,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
    expire_on_commit=False,
    future=True,
)
