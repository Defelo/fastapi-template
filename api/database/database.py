from asyncio import Event
from contextvars import ContextVar
from typing import Any, AsyncIterator, Type, TypeVar, cast

from sqlalchemy import Column
from sqlalchemy.engine import URL, Result
from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.future import select as sa_select
from sqlalchemy.orm import DeclarativeMeta, registry, selectinload
from sqlalchemy.sql import Executable
from sqlalchemy.sql.expression import Delete
from sqlalchemy.sql.expression import delete as sa_delete
from sqlalchemy.sql.expression import exists as sa_exists
from sqlalchemy.sql.functions import count
from sqlalchemy.sql.selectable import Exists, Select

from ..environment import (
    DB_DATABASE,
    DB_DRIVER,
    DB_HOST,
    DB_PASSWORD,
    DB_PORT,
    DB_USERNAME,
    MAX_OVERFLOW,
    POOL_RECYCLE,
    POOL_SIZE,
    SQL_SHOW_STATEMENTS,
)
from ..logger import get_logger


T = TypeVar("T")

logger = get_logger(__name__)


def select(entity: Any, *args: Column[Any]) -> Select:
    """Shortcut for :meth:`sqlalchemy.future.select`"""

    if not args:
        return sa_select(entity)

    options = []
    for arg in args:
        if isinstance(arg, (tuple, list)):
            head, *tail = arg
            opt = selectinload(head)
            for x in tail:
                opt = opt.selectinload(x)
            options.append(opt)
        else:
            options.append(selectinload(arg))

    return sa_select(entity).options(*options)


def filter_by(cls: Any, *args: Column[Any], **kwargs: Any) -> Select:
    """Shortcut for :meth:`sqlalchemy.future.Select.filter_by`"""

    return select(cls, *args).filter_by(**kwargs)


def exists(statement: Executable, *entities: Column[Any], **kwargs: Any) -> Exists:
    """Shortcut for :meth:`sqlalchemy.future.select`"""

    return sa_exists(statement, *entities, **kwargs)


def delete(table: Any) -> Delete:
    """Shortcut for :meth:`sqlalchemy.sql.expression.delete`"""

    return sa_delete(table)


class Base(metaclass=DeclarativeMeta):
    __abstract__ = True
    registry = registry()
    metadata = registry.metadata

    __table_args__ = {"mysql_collate": "utf8mb4_bin"}

    def __init__(self, **kwargs: Any) -> None:
        self.registry.constructor(self, **kwargs)


class DB:
    def __init__(self, url: URL, **kwargs: Any):
        self.engine: AsyncEngine = create_async_engine(url, **kwargs)
        self._session: ContextVar[AsyncSession | None] = ContextVar("session", default=None)
        self._close_event: ContextVar[Event | None] = ContextVar("close_event", default=None)

    async def create_tables(self) -> None:
        """Create all tables defined in enabled cog packages."""

        logger.debug("creating tables")
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

    async def add(self, obj: T) -> T:
        """
        Add a new row to the database

        :param obj: the row to insert
        :return: the same row
        """

        self.session.add(obj)
        return obj

    async def delete(self, obj: T) -> T:
        """
        Remove a row from the database

        :param obj: the row to remove
        :return: the same row
        """

        await self.session.delete(obj)
        return obj

    async def exec(self, statement: Executable | str) -> Result:
        """Execute an sql statement and return the result."""

        return await self.session.execute(cast(Executable, statement))

    async def stream(self, statement: Executable | str) -> AsyncIterator[Any]:
        """Execute an sql statement and stream the result."""

        return cast(AsyncIterator[Any], (await self.session.stream(statement)).scalars())

    async def all(self, statement: Executable | str) -> list[Any]:
        """Execute an sql statement and return all results as a list."""

        return [x async for x in await self.stream(statement)]

    async def first(self, statement: Executable | str) -> Any | None:
        """Execute an sql statement and return the first result."""

        return (await self.exec(statement)).scalar()

    async def exists(self, statement: Executable | str, *args: Column[Any], **kwargs: Any) -> bool:
        """Execute an sql statement and return whether it returned at least one row."""

        return cast(bool, await self.first(exists(cast(Executable, statement), *args, **kwargs).select()))

    async def count(self, statement: Select) -> int:
        """Execute an sql statement and return the number of returned rows."""

        return cast(int, await self.first(select(count()).select_from(statement.subquery())))

    async def get(self, cls: Type[T], *args: Column[Any], **kwargs: Any) -> T | None:
        """Shortcut for first(filter_by(...))"""

        return await self.first(filter_by(cls, *args, **kwargs))

    async def commit(self) -> None:
        """Shortcut for :meth:`sqlalchemy.ext.asyncio.AsyncSession.commit`"""

        if self._session.get():
            await self.session.commit()

    async def close(self) -> None:
        """Close the current session"""

        if self._session.get():
            await self.session.close()
            if close_event := self._close_event.get():
                close_event.set()

    def create_session(self) -> AsyncSession:
        """Create a new async session and store it in the context variable."""

        self._session.set(session := AsyncSession(self.engine))
        self._close_event.set(Event())
        return session

    @property
    def session(self) -> AsyncSession:
        """Get the session object for the current task"""

        return cast(AsyncSession, self._session.get())

    async def wait_for_close_event(self) -> None:
        if close_event := self._close_event.get():
            await close_event.wait()


def get_url() -> URL:
    return URL.create(
        drivername=DB_DRIVER,
        username=DB_USERNAME,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT,
        database=DB_DATABASE,
    )


def get_database() -> DB:
    """
    Create a database connection object using the environment variables

    :return: The DB object
    """

    return DB(
        url=get_url(),
        pool_pre_ping=True,
        pool_recycle=POOL_RECYCLE,
        pool_size=POOL_SIZE,
        max_overflow=MAX_OVERFLOW,
        echo=SQL_SHOW_STATEMENTS,
    )
