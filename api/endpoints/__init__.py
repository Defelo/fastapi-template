from .oauth import router as oauth
from .recaptcha import router as recaptcha
from .session import router as session
from .test import router as test
from .user import router as user

ROUTERS = [user, session, oauth, recaptcha, test]
