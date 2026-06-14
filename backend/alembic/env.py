from logging.config import fileConfig
from sqlalchemy import engine_from_config, pool
from alembic import context
import asyncio
from sqlalchemy.ext.asyncio import create_async_engine

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

from app.database import Base
from app.models import *

target_metadata = Base.metadata


def run_migrations_offline():
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    connectable = create_async_engine(config.get_main_option("sqlalchemy.url"))
    async def run():
        async with connectable.connect() as connection:
            await connection.run_sync(do_run_migrations)
    asyncio.run(run())


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
