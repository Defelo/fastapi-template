from .oauth import router as _oauth
from .recaptcha import router as _recaptcha
from .session import router as _session
from .test import router as _test
from .user import router as _user


ROUTERS = [_user, _session, _oauth, _recaptcha, _test]
