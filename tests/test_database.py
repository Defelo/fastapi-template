from contextvars import ContextVar
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, MagicMock, call

import pytest
from _pytest.monkeypatch import MonkeyPatch
from pytest_mock import MockerFixture
from sqlalchemy.orm import DeclarativeMeta, registry

from ._utils import import_module, mock_asynccontextmanager, mock_dict, mock_list
from api import database
from api.settings import settings


@pytest.mark.parametrize(
    "entity,args,expected",
    [
        ("my entity", [], call.sa_select("my entity")),
        (
            "asdf",
            ["col1", "col2"],
            call.sa_select("asdf").options(call.selectinload("col1"), call.selectinload("col2")),
        ),
        (
            "FooBar42",
            [(1, "foo"), ["bar", 2]],
            call.sa_select("FooBar42").options(
                call.selectinload(1).selectinload("foo"), call.selectinload("bar").selectinload(2)
            ),
        ),
        (
            "qwertz",
            ["xyz", ["A", "B", "C", 42], "foo", (42, [1337])],
            call.sa_select("qwertz").options(
                call.selectinload("xyz"),
                call.selectinload("A").selectinload("B").selectinload("C").selectinload(42),
                call.selectinload("foo"),
                call.selectinload(42).selectinload([1337]),
            ),
        ),
    ],
)
async def test__select(mocker: MockerFixture, entity: Any, args: list[Any], expected: Any) -> None:
    sa_select_patch = mocker.patch("api.database.database.sa_select")
    selectinload_patch = mocker.patch("api.database.database.selectinload")
    sa_select_patch.side_effect = call.sa_select
    selectinload_patch.side_effect = call.selectinload

    assert database.select(entity, *args) == expected


def test__filter_by(mocker: MockerFixture) -> None:
    select_patch = mocker.patch("api.database.database.select")

    cls = MagicMock()
    args = mock_list(5)
    kwargs = mock_dict(5, string_keys=True)

    result = database.filter_by(cls, *args, **kwargs)

    select_patch.assert_called_once_with(cls, *args)
    select_patch().filter_by.assert_called_once_with(**kwargs)
    assert result == select_patch().filter_by()


async def test__exists(mocker: MockerFixture) -> None:
    sa_exists_patch = mocker.patch("api.database.database.sa_exists")

    args = mock_list(5)
    kwargs = mock_dict(5, True)

    result = database.database.exists(*args, **kwargs)

    sa_exists_patch.assert_called_once_with(*args, **kwargs)
    assert result == sa_exists_patch()


async def test__delete(mocker: MockerFixture) -> None:
    sa_delete_patch = mocker.patch("api.database.database.sa_delete")

    table = MagicMock()

    result = database.database.delete(table)

    sa_delete_patch.assert_called_once_with(table)
    assert result == sa_delete_patch()


async def test__base() -> None:
    assert isinstance(database.Base, DeclarativeMeta)
    assert database.Base.__abstract__ is True
    assert isinstance(database.Base.registry, registry)
    assert database.Base.registry.metadata == database.Base.metadata


async def test__base_constructor() -> None:
    base = MagicMock()
    kwargs = mock_dict(5, string_keys=True)

    database.Base.__init__(base, **kwargs)

    base.registry.constructor.assert_called_once_with(base, **kwargs)


async def test__constructor(mocker: MockerFixture) -> None:
    create_async_engine_patch = mocker.patch("api.database.database.create_async_engine")

    url = MagicMock()
    kwargs = mock_dict(5, string_keys=True)

    result = database.database.DB(url, **kwargs)

    create_async_engine_patch.assert_called_once_with(url, **kwargs)
    assert result.engine == create_async_engine_patch()

    assert isinstance(result._session, ContextVar)
    assert result._session.name == "session"
    assert result._session.get() is None

    assert isinstance(result._close_event, ContextVar)
    assert result._close_event.name == "close_event"
    assert result._close_event.get() is None


async def test__create_tables(mocker: MockerFixture) -> None:
    base_patch = mocker.patch("api.database.database.Base")

    db = MagicMock()

    async def run_sync(coro: Any) -> None:
        assert coro == base_patch.metadata.create_all
        func_callback()

    conn = MagicMock()
    conn.run_sync = run_sync
    db.engine.begin, [func_callback], assert_calls = mock_asynccontextmanager(1, conn)

    await database.database.DB.create_tables(db)

    assert_calls()


async def test__add() -> None:
    db = MagicMock()
    obj = MagicMock()

    result = await database.database.DB.add(db, obj)

    db.session.add.assert_called_once_with(obj)
    assert obj == result


async def test__db__delete() -> None:
    db = AsyncMock()
    obj = MagicMock()

    result = await database.database.DB.delete(db, obj)

    db.session.delete.assert_called_once_with(obj)
    assert obj == result


async def test__exec() -> None:
    db = AsyncMock()
    statement = MagicMock()

    result = await database.database.DB.exec(db, statement)

    db.session.execute.assert_called_once_with(statement)
    assert result == await db.session.execute()


async def test__stream() -> None:
    db = AsyncMock()
    statement = MagicMock()
    db.session.stream.return_value = MagicMock()

    result = await database.database.DB.stream(db, statement)

    db.session.stream.assert_called_once_with(statement)
    (await db.session.stream()).scalars.assert_called_once_with()
    assert result == (await db.session.stream()).scalars()


async def test__all() -> None:
    db = AsyncMock()
    statement = MagicMock()
    expected = mock_list(5)

    async def async_iterator() -> AsyncIterator[Any]:
        for x in expected:
            yield x

    db.stream.return_value = async_iterator()

    result = await database.database.DB.all(db, statement)

    db.stream.assert_called_once_with(statement)
    assert result == expected


async def test__first() -> None:
    db = AsyncMock()
    statement = MagicMock()
    db.exec.return_value = MagicMock()

    result = await database.database.DB.first(db, statement)

    db.exec.assert_called_once_with(statement)
    (await db.exec()).scalar.assert_called_once_with()
    assert result == (await db.exec()).scalar()


async def test__db__exists(mocker: MockerFixture) -> None:
    exists_patch = mocker.patch("api.database.database.exists")

    db = AsyncMock()
    args = mock_list(5)
    kwargs = mock_dict(5, True)

    result = await database.database.DB.exists(db, *args, **kwargs)

    exists_patch.assert_called_once_with(*args, **kwargs)
    exists_patch().select.assert_called_once_with()
    db.first.assert_called_once_with(exists_patch().select())
    assert result == await db.first(exists_patch().select())


async def test__db__count(mocker: MockerFixture) -> None:
    count_patch = mocker.patch("api.database.database.count")
    select_patch = mocker.patch("api.database.database.select")

    db = AsyncMock()
    arg = MagicMock()

    result = await database.database.DB.count(db, arg)

    count_patch.assert_called_once_with()
    select_patch.assert_called_once_with(count_patch())
    arg.subquery.assert_called_once_with()
    select_patch().select_from.assert_called_once_with(arg.subquery())
    db.first.assert_called_once_with(select_patch().select_from())
    assert result == await db.first()


async def test__get(mocker: MockerFixture) -> None:
    filter_by_patch = mocker.patch("api.database.database.filter_by")

    db = AsyncMock()
    args = mock_list(5)
    kwargs = mock_dict(5, True)

    result = await database.database.DB.get(db, *args, **kwargs)  # type: ignore

    filter_by_patch.assert_called_once_with(*args, **kwargs)
    db.first.assert_called_once_with(filter_by_patch())
    assert result == await db.first()


async def test__commit__no_session() -> None:
    db = MagicMock()
    db._session.get.return_value = None
    db.session = AsyncMock()

    await database.database.DB.commit(db)

    db._session.get.assert_called_once_with()
    db.session.commit.assert_not_called()


async def test__commit__with_session() -> None:
    db = MagicMock()
    session = db._session.get.return_value = db.session = MagicMock()
    session.commit = AsyncMock()

    await database.database.DB.commit(db)

    db._session.get.assert_called_once_with()
    session.commit.assert_called_once_with()


async def test__close__no_session() -> None:
    db = MagicMock()
    db._session.get.return_value = None
    db.session = AsyncMock()

    await database.database.DB.close(db)

    db._session.get.assert_called_once_with()
    db.session.close.assert_not_called()
    db._close_event.get().set.assert_not_called()


async def test__close__with_session_no_close_event() -> None:
    db = MagicMock()
    session = db._session.get.return_value = db.session = MagicMock()
    session.close = AsyncMock()
    db._close_event.get.return_value = None

    await database.database.DB.close(db)

    db._session.get.assert_called_once_with()
    session.close.assert_called_once_with()
    db._close_event.get.assert_called_once_with()


async def test__close__with_session() -> None:
    db = MagicMock()
    session = db._session.get.return_value = db.session = MagicMock()
    session.close = AsyncMock()

    await database.database.DB.close(db)

    db._session.get.assert_called_once_with()
    session.close.assert_called_once_with()
    db._close_event.get.assert_called_once_with()
    db._close_event.get().set.assert_called_once_with()


async def test__create_session(mocker: MockerFixture) -> None:
    async_session_patch = mocker.patch("api.database.database.AsyncSession")
    event_patch = mocker.patch("api.database.database.Event")

    db = MagicMock()

    result = database.database.DB.create_session(db)

    async_session_patch.assert_called_once_with(db.engine)
    db._session.set.assert_called_with(async_session_patch())
    event_patch.assert_called_once_with()
    db._close_event.set.assert_called_with(event_patch())
    assert result == async_session_patch()


async def test__session() -> None:
    db = MagicMock()

    result = database.database.DB.session.fget(db)  # type: ignore

    db._session.get.assert_called_once_with()
    assert result == db._session.get()


async def test__wait_for_close_event__not_set() -> None:
    db = MagicMock()
    db._close_event.get.return_value = None

    await database.database.DB.wait_for_close_event(db)

    db._close_event.get.assert_called_once_with()


async def test__wait_for_close_event() -> None:
    db = MagicMock()
    close_event = db._close_event.get.return_value = MagicMock()
    close_event.wait = AsyncMock()

    await database.database.DB.wait_for_close_event(db)

    db._close_event.get.assert_called_once_with()
    close_event.wait.assert_called_once_with()


async def test__get_database(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    db_patch = mocker.patch("api.database.database.DB")

    monkeypatch.setattr(settings, "database_url", url_patch := MagicMock())
    monkeypatch.setattr(settings, "pool_recycle", pool_recycle_patch := MagicMock())
    monkeypatch.setattr(settings, "pool_size", pool_size_patch := MagicMock())
    monkeypatch.setattr(settings, "max_overflow", max_overflow_patch := MagicMock())
    monkeypatch.setattr(settings, "sql_show_statements", sql_show_statements_patch := MagicMock())

    result = database.database.get_database()

    db_patch.assert_called_once_with(
        url=url_patch,
        pool_pre_ping=True,
        pool_recycle=pool_recycle_patch,
        pool_size=pool_size_patch,
        max_overflow=max_overflow_patch,
        echo=sql_show_statements_patch,
    )
    assert result == db_patch()


async def test__db_context(mocker: MockerFixture) -> None:
    db_patch = mocker.patch("api.database.db")

    db_patch.commit = AsyncMock()
    db_patch.close = AsyncMock()
    db_patch.close.side_effect = lambda: db_patch.commit.assert_called_once_with()

    async with database.db_context():
        db_patch.create_session.assert_called_once_with()

    db_patch.close.assert_called_once_with()


async def test__db_wrapper(mocker: MockerFixture) -> None:
    db_context_patch = mocker.patch("api.database.db_context")
    db_context_patch.side_effect, [func_callback], assert_calls = mock_asynccontextmanager(1, None)

    args = mock_list(5)
    kwargs = mock_dict(5, True)
    expected = MagicMock()

    @database.db_wrapper
    async def test(*_args: Any, **_kwargs: Any) -> Any:
        assert args == list(_args)
        assert kwargs == _kwargs
        func_callback()
        return expected

    result = await test(*args, **kwargs)

    assert result == expected
    db_context_patch.assert_called_once_with()
    assert_calls()
    assert test.__name__ == "test"


async def test__db(mocker: MockerFixture) -> None:
    get_database_mock = mocker.patch("api.database.database.get_database")

    db = import_module("api.database")

    get_database_mock.assert_called_once_with()
    assert get_database_mock() == db.db
