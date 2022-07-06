from contextlib import asynccontextmanager
from contextvars import ContextVar
from typing import Any, AsyncIterator
from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, call, patch

from parameterized import parameterized
from sqlalchemy.orm import DeclarativeMeta, registry
from utils import AsyncMock, import_module, mock_dict, mock_list

from api import database


class TestDatabase(IsolatedAsyncioTestCase):
    @parameterized.expand(
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
        ]
    )  # type: ignore
    async def test__select(self, entity: Any, args: list[Any], expected: Any) -> None:
        with patch("api.database.database.sa_select") as sa_select_patch, patch(
            "api.database.database.selectinload"
        ) as selectinload_patch:
            sa_select_patch.side_effect = call.sa_select
            selectinload_patch.side_effect = call.selectinload

            actual = database.select(entity, *args)

            self.assertEqual(actual, expected)

    @patch("api.database.database.select")
    def test__filter_by(self, select_patch: MagicMock) -> None:
        cls = MagicMock()
        args = mock_list(5)
        kwargs = mock_dict(5, string_keys=True)

        result = database.filter_by(cls, *args, **kwargs)

        select_patch.assert_called_once_with(cls, *args)
        select_patch().filter_by.assert_called_once_with(**kwargs)
        self.assertEqual(select_patch().filter_by(), result)

    @patch("api.database.database.sa_exists")
    async def test__exists(self, sa_exists_patch: MagicMock) -> None:
        args = mock_list(5)
        kwargs = mock_dict(5, True)

        result = database.database.exists(*args, **kwargs)

        sa_exists_patch.assert_called_once_with(*args, **kwargs)
        self.assertEqual(sa_exists_patch(), result)

    @patch("api.database.database.sa_delete")
    async def test__delete(self, sa_delete_patch: MagicMock) -> None:
        table = MagicMock()

        result = database.database.delete(table)

        sa_delete_patch.assert_called_once_with(table)
        self.assertEqual(sa_delete_patch(), result)

    async def test__base(self) -> None:
        self.assertIsInstance(database.Base, DeclarativeMeta)
        self.assertEqual(True, database.Base.__abstract__)
        self.assertIsInstance(database.Base.registry, registry)
        self.assertEqual(database.Base.registry.metadata, database.Base.metadata)

    async def test__base_constructor(self) -> None:
        base = MagicMock()
        kwargs = mock_dict(5, string_keys=True)

        database.Base.__init__(base, **kwargs)

        base.registry.constructor.assert_called_once_with(base, **kwargs)

    @patch("api.database.database.URL.create")
    @patch("api.database.database.create_async_engine")
    async def test__constructor(self, create_async_engine_patch: MagicMock, url_create_patch: MagicMock) -> None:
        driver = MagicMock()
        host = MagicMock()
        port = MagicMock()
        db = MagicMock()
        username = MagicMock()
        password = MagicMock()
        pool_recycle = MagicMock()
        pool_size = MagicMock()
        max_overflow = MagicMock()
        echo = MagicMock()

        result = database.database.DB(
            driver, host, port, db, username, password, pool_recycle, pool_size, max_overflow, echo
        )

        url_create_patch.assert_called_once_with(
            drivername=driver, username=username, password=password, host=host, port=port, database=db
        )
        create_async_engine_patch.assert_called_once_with(
            url_create_patch(),
            pool_pre_ping=True,
            pool_recycle=pool_recycle,
            pool_size=pool_size,
            max_overflow=max_overflow,
            echo=echo,
        )
        self.assertEqual(create_async_engine_patch(), result.engine)

        self.assertIsInstance(result._session, ContextVar)
        self.assertEqual("session", result._session.name)
        self.assertEqual(None, result._session.get())

        self.assertIsInstance(result._close_event, ContextVar)
        self.assertEqual("close_event", result._close_event.name)
        self.assertEqual(None, result._close_event.get())

    @patch("api.database.database.logger")
    @patch("api.database.database.Base")
    async def test__create_tables(self, base_patch: MagicMock, _: Any) -> None:
        db = MagicMock()

        events = []

        async def run_sync(coro: Any) -> None:
            self.assertEqual(base_patch.metadata.create_all, coro)
            events.append(1)

        @asynccontextmanager
        async def context_manager() -> AsyncIterator[Any]:
            events.append(0)

            conn = MagicMock()
            conn.run_sync = run_sync
            yield conn

            events.append(2)

        db.engine.begin = context_manager

        await database.database.DB.create_tables(db)

        self.assertEqual([0, 1, 2], events)

    async def test__add(self) -> None:
        db = MagicMock()
        obj = MagicMock()

        result = await database.database.DB.add(db, obj)

        db.session.add.assert_called_once_with(obj)
        self.assertEqual(obj, result)

    async def test__db__delete(self) -> None:
        db = AsyncMock()
        obj = MagicMock()

        result = await database.database.DB.delete(db, obj)

        db.session.delete.assert_called_once_with(obj)
        self.assertEqual(obj, result)

    async def test__exec(self) -> None:
        db = AsyncMock()
        statement = MagicMock()

        result = await database.database.DB.exec(db, statement)

        db.session.execute.assert_called_once_with(statement)
        self.assertEqual(db.session.execute(), result)

    async def test__stream(self) -> None:
        db = AsyncMock()
        statement = MagicMock()
        db.session.stream.return_value = MagicMock()

        result = await database.database.DB.stream(db, statement)

        db.session.stream.assert_called_once_with(statement)
        (await db.session.stream()).scalars.assert_called_once_with()
        self.assertEqual((await db.session.stream()).scalars(), result)

    async def test__all(self) -> None:
        db = AsyncMock()
        statement = MagicMock()
        expected = mock_list(5)

        async def async_iterator() -> AsyncIterator[Any]:
            for x in expected:
                yield x

        db.stream.return_value = async_iterator()

        result = await database.database.DB.all(db, statement)

        db.stream.assert_called_once_with(statement)
        self.assertEqual(expected, result)

    async def test__first(self) -> None:
        db = AsyncMock()
        statement = MagicMock()
        db.exec.return_value = MagicMock()

        result = await database.database.DB.first(db, statement)

        db.exec.assert_called_once_with(statement)
        (await db.exec()).scalar.assert_called_once_with()
        self.assertEqual((await db.exec()).scalar(), result)

    @patch("api.database.database.exists")
    async def test__db__exists(self, exists_patch: MagicMock) -> None:
        db = AsyncMock()
        args = mock_list(5)
        kwargs = mock_dict(5, True)

        result = await database.database.DB.exists(db, *args, **kwargs)

        exists_patch.assert_called_once_with(*args, **kwargs)
        exists_patch().select.assert_called_once_with()
        db.first.assert_called_once_with(exists_patch().select())
        self.assertEqual(db.first(exists_patch().select()), result)

    @patch("api.database.database.count")
    @patch("api.database.database.select")
    async def test__db__count(self, select_patch: MagicMock, count_patch: MagicMock) -> None:
        db = AsyncMock()
        args = mock_list(5)

        result = await database.database.DB.count(db, *args)

        count_patch.assert_called_once_with()
        select_patch.assert_called_once_with(count_patch())
        select_patch().select_from.assert_called_once_with(*args)
        db.first.assert_called_once_with(select_patch().select_from())
        self.assertEqual(db.first(), result)

    @patch("api.database.database.filter_by")
    async def test__get(self, filter_by_patch: MagicMock) -> None:
        db = AsyncMock()
        args = mock_list(5)
        kwargs = mock_dict(5, True)

        result = await database.database.DB.get(db, *args, **kwargs)

        filter_by_patch.assert_called_once_with(*args, **kwargs)
        db.first.assert_called_once_with(filter_by_patch())
        self.assertEqual(db.first(), result)

    async def test__commit__no_session(self) -> None:
        db = MagicMock()
        db._session.get.return_value = None
        db.session = AsyncMock()

        await database.database.DB.commit(db)

        db._session.get.assert_called_once_with()
        db.session.commit.assert_not_called()

    async def test__commit__with_session(self) -> None:
        db = MagicMock()
        session = db._session.get.return_value = db.session = MagicMock()
        session.commit = AsyncMock()

        await database.database.DB.commit(db)

        db._session.get.assert_called_once_with()
        session.commit.assert_called_once_with()

    async def test__close__no_session(self) -> None:
        db = MagicMock()
        db._session.get.return_value = None
        db.session = AsyncMock()

        await database.database.DB.close(db)

        db._session.get.assert_called_once_with()
        db.session.close.assert_not_called()
        db._close_event.get().set.assert_not_called()

    async def test__close__with_session_no_close_event(self) -> None:
        db = MagicMock()
        session = db._session.get.return_value = db.session = MagicMock()
        session.close = AsyncMock()
        db._close_event.get.return_value = None

        await database.database.DB.close(db)

        db._session.get.assert_called_once_with()
        session.close.assert_called_once_with()
        db._close_event.get.assert_called_once_with()

    async def test__close__with_session(self) -> None:
        db = MagicMock()
        session = db._session.get.return_value = db.session = MagicMock()
        session.close = AsyncMock()

        await database.database.DB.close(db)

        db._session.get.assert_called_once_with()
        session.close.assert_called_once_with()
        db._close_event.get.assert_called_once_with()
        db._close_event.get().set.assert_called_once_with()

    @patch("api.database.database.Event")
    @patch("api.database.database.AsyncSession")
    async def test__create_session(self, asyncsession_patch: MagicMock, event_patch: MagicMock) -> None:
        db = MagicMock()

        result = database.database.DB.create_session(db)

        asyncsession_patch.assert_called_once_with(db.engine)
        db._session.set.assert_called_with(asyncsession_patch())
        event_patch.assert_called_once_with()
        db._close_event.set.assert_called_with(event_patch())
        self.assertEqual(asyncsession_patch(), result)

    async def test__session(self) -> None:
        db = MagicMock()

        # noinspection PyArgumentList
        result = database.database.DB.session.fget(db)  # type: ignore

        db._session.get.assert_called_once_with()
        self.assertEqual(db._session.get(), result)

    async def test__wait_for_close_event__not_set(self) -> None:
        db = MagicMock()
        db._close_event.get.return_value = None

        await database.database.DB.wait_for_close_event(db)

        db._close_event.get.assert_called_once_with()

    async def test__wait_for_close_event(self) -> None:
        db = MagicMock()
        close_event = db._close_event.get.return_value = MagicMock()
        close_event.wait = AsyncMock()

        await database.database.DB.wait_for_close_event(db)

        db._close_event.get.assert_called_once_with()
        close_event.wait.assert_called_once_with()

    @patch("api.database.database.SQL_SHOW_STATEMENTS")
    @patch("api.database.database.MAX_OVERFLOW")
    @patch("api.database.database.POOL_SIZE")
    @patch("api.database.database.POOL_RECYCLE")
    @patch("api.database.database.DB_PASSWORD")
    @patch("api.database.database.DB_USERNAME")
    @patch("api.database.database.DB_DATABASE")
    @patch("api.database.database.DB_PORT")
    @patch("api.database.database.DB_HOST")
    @patch("api.database.database.DB_DRIVER")
    @patch("api.database.database.DB")
    async def test__get_database(
        self,
        db_patch: MagicMock,
        db_driver_patch: MagicMock,
        db_host_patch: MagicMock,
        db_port_patch: MagicMock,
        db_database_patch: MagicMock,
        db_username_patch: MagicMock,
        db_password_patch: MagicMock,
        pool_recycle_patch: MagicMock,
        pool_size_patch: MagicMock,
        max_overflow_patch: MagicMock,
        sql_show_statements_patch: MagicMock,
    ) -> None:
        result = database.database.get_database()

        db_patch.assert_called_once_with(
            driver=db_driver_patch,
            host=db_host_patch,
            port=db_port_patch,
            database=db_database_patch,
            username=db_username_patch,
            password=db_password_patch,
            pool_recycle=pool_recycle_patch,
            pool_size=pool_size_patch,
            max_overflow=max_overflow_patch,
            echo=sql_show_statements_patch,
        )
        self.assertEqual(result, db_patch())

    @patch("api.database.db")
    async def test__db_context(self, db_patch: MagicMock) -> None:
        db_patch.commit = AsyncMock()
        db_patch.close = AsyncMock()
        db_patch.close.side_effect = lambda: db_patch.commit.assert_called_once_with()

        async with database.db_context():
            db_patch.create_session.assert_called_once_with()

        db_patch.close.assert_called_once_with()

    @patch("api.database.db_context")
    async def test__db_wrapper(self, db_context_patch: MagicMock) -> None:
        events = []
        args = mock_list(5)
        kwargs = mock_dict(5, True)
        expected = MagicMock()

        @database.db_wrapper
        async def test(*_args: Any, **_kwargs: Any) -> Any:
            self.assertEqual(args, list(_args))
            self.assertEqual(kwargs, _kwargs)
            events.append(1)
            return expected

        @asynccontextmanager
        async def context_manager() -> AsyncIterator[None]:
            events.append(0)
            yield
            events.append(2)

        db_context_patch.side_effect = context_manager

        result = await test(*args, **kwargs)

        self.assertEqual(expected, result)
        db_context_patch.assert_called_once_with()
        self.assertEqual([0, 1, 2], events)
        self.assertEqual("test", test.__name__)

    async def test__db(self) -> None:
        old_get_database = database.database.get_database
        get_database_mock = database.database.get_database = MagicMock()

        try:
            db = import_module("api.database")

            get_database_mock.assert_called_once_with()
            self.assertEqual(get_database_mock(), db.db)
        finally:
            database.database.get_database = old_get_database
