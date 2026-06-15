import os
import sys
from logging.config import fileConfig
from alembic import context
from sqlalchemy import engine_from_config, pool
from sqlalchemy.ext.asyncio import create_async_engine

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

from app.database import Base
from app.models import *

target_metadata = Base.metadata


def get_url():
    url = os.environ.get("DATABASE_URL", config.get_main_option("sqlalchemy.url"))
    if url and url.startswith("sqlite"):
        url = url.replace("sqlite+aiosqlite", "sqlite+pysqlite")
        url = url.replace("sqlite+asyncpg", "sqlite+pysqlite")
    return url


def run_migrations_offline():
    url = get_url().replace("+aiosqlite", "").replace("+asyncpg", "")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    url = get_url()
    if url.startswith("sqlite"):
        from sqlalchemy import create_engine
        connectable = create_engine(url)
        with connectable.connect() as connection:
            context.configure(connection=connection, target_metadata=target_metadata)
            with context.begin_transaction():
                context.run_migrations()
    else:
        connectable = create_async_engine(url)
        async def run():
            async with connectable.connect() as connection:
                await connection.run_sync(do_run_migrations)
        import asyncio
        asyncio.run(run())


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
