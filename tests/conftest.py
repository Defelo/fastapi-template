from sqlalchemy.sql import Select
from sqlalchemy.sql.expression import Delete
from starlette.exceptions import HTTPException

from api.app import app


pytest_plugins = "tests.fixtures"

Select.__eq__ = Select.compare  # type: ignore
Delete.__eq__ = Delete.compare  # type: ignore

del app.user_middleware[0]  # remove db session for tests
del app.exception_handlers[HTTPException]  # remove auto db rollback for tests
app.middleware_stack = app.build_middleware_stack()
